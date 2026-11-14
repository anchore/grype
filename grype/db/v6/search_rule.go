package v6

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// SearchRuleProvider is implemented by providers that evaluate search rules.
type SearchRuleProvider interface {
	// SearchRewrites returns the searches to run in place of cs, one per distinct search, where each
	// search a rule added carries a search.RuleCriteria. It is false when no rule applies, and cs is
	// searched as is. p is the package the rules are evaluated against unless cs has a
	// search.WithPackage criteria.
	SearchRewrites(p pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool)
}

func (o SearchRule) Validate() error {
	_, err := compileSearchRule(o)
	return err
}

// isOSLessSearch is true for an empty, non-NULL ReplacementDistroName, which searches the rows of no
// OS.
func (o SearchRule) isOSLessSearch() bool {
	return o.ReplacementDistroName != nil && *o.ReplacementDistroName == ""
}

// String describes the rule by its action, the columns it sets and its priority, for logging.
func (o SearchRule) String() string {
	var sb strings.Builder
	sb.WriteString(string(o.Action))
	var upstream *string
	if o.MatchUpstreamSearch != nil {
		upstream = ptr(strconv.FormatBool(*o.MatchUpstreamSearch))
	}
	for _, c := range []struct {
		column string
		value  *string // nil for a column the rule does not set
	}{
		{"match_distro_name", setString(o.MatchDistroName)},
		{"match_distro_version", setString(o.MatchDistroVersion)},
		{"match_distro_channel", setString(o.MatchDistroChannel)},
		{"match_ecosystem", setString(o.MatchEcosystem)},
		{"match_package_name", setString(o.MatchPackageName)},
		{"exclude_package_name", setString(o.ExcludePackageName)},
		{"match_package_version", setString(o.MatchPackageVersion)},
		{"exclude_package_version", setString(o.ExcludePackageVersion)},
		{"match_cpe_vendor", setString(o.MatchCPEVendor)},
		{"exclude_cpe_vendor", setString(o.ExcludeCPEVendor)},
		{"match_cpe_product", setString(o.MatchCPEProduct)},
		{"exclude_cpe_product", setString(o.ExcludeCPEProduct)},
		{"match_upstream_search", upstream},
		{"replacement_channel", o.ReplacementChannel},
		{"replacement_distro_name", o.ReplacementDistroName},
		{"replacement_distro_version", o.ReplacementDistroVersion},
		{"replacement_distro_label_version", o.ReplacementDistroLabelVersion},
		{"replacement_package_name", setString(o.ReplacementPackageName)},
		{"replacement_ecosystem", setString(o.ReplacementEcosystem)},
		{"replacement_cpe_vendor", setString(o.ReplacementCPEVendor)},
		{"replacement_cpe_product", setString(o.ReplacementCPEProduct)},
		{"applicable_client_db_schemas", setString(o.ApplicableClientDBSchemas)},
	} {
		if c.value == nil {
			continue
		}
		value := *c.value
		if value == "" {
			value = `""`
		}
		sb.WriteString(" " + c.column + "=" + value)
	}
	if o.Priority != 0 {
		sb.WriteString(" priority=" + strconv.Itoa(o.Priority))
	}
	return sb.String()
}

// setString is s, or nil for an empty column.
func setString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// hasCPEReplacement is true for a rule that searches another CPE vendor and/or product.
func (o SearchRule) hasCPEReplacement() bool {
	return o.ReplacementCPEVendor != "" || o.ReplacementCPEProduct != ""
}

// hasPackageSearchReplacement is true for a rule that searches another package name, ecosystem and/or
// OS.
func (o SearchRule) hasPackageSearchReplacement() bool {
	return o.ReplacementChannel != nil || o.ReplacementDistroName != nil || o.ReplacementDistroVersion != nil ||
		o.ReplacementDistroLabelVersion != nil || o.ReplacementPackageName != "" || o.ReplacementEcosystem != ""
}

// searchSubject is what one search states about the package it searches for.
type searchSubject struct {
	name      string
	version   string
	ecosystem string
	distro    *distro.Distro

	// of the searched CPE; empty for a search by no CPE
	cpeVendor, cpeProduct string

	// for one of the package's upstream (source) packages rather than the package itself
	upstream bool
}

// matchType is which of the search's values a Match*/Exclude* column matches. A match captures the
// matched value under its name (e.g. ${package_name}), which no pattern may define a group of.
type matchType string

const (
	distroName     matchType = "distro_name"
	distroVersion  matchType = "distro_version"
	distroChannel  matchType = "distro_channel"
	ecosystem      matchType = "ecosystem"
	packageName    matchType = "package_name"
	packageVersion matchType = "package_version"
	cpeVendor      matchType = "cpe_vendor"
	cpeProduct     matchType = "cpe_product"
)

// values are the search's values to try, in order: the first n of values, none when the search does
// not state them or t is no match type.
func (t matchType) values(s searchSubject) (values [2]string, n int) {
	switch t {
	case distroName:
		values[0] = distroNameOf(s.distro)
	case distroVersion:
		// the release version, then the version label, as OSSpecifier.matchesVersionPattern does
		if s.distro != nil {
			values[0], values[1] = s.distro.Version, s.distro.LabelVersion()
		}
	case distroChannel:
		// an OS is searched with at most a channel or two (e.g. "eus")
		if s.distro != nil {
			copy(values[:], s.distro.Channels)
		}
	case ecosystem:
		values[0] = s.ecosystem
	case packageName:
		values[0] = s.name
	case packageVersion:
		values[0] = s.version
	case cpeVendor:
		values[0] = s.cpeVendor
	case cpeProduct:
		values[0] = s.cpeProduct
	}
	for _, v := range values {
		if v != "" {
			values[n] = v
			n++
		}
	}
	return values, n
}

// firstValue is the value a reference to t resolves to when no pattern captured it.
func (t matchType) firstValue(s searchSubject) string {
	values, n := t.values(s)
	if n == 0 {
		return ""
	}
	return values[0]
}

func (t matchType) isValid() bool {
	switch t {
	case distroName, distroVersion, distroChannel, ecosystem, packageName, packageVersion, cpeVendor, cpeProduct:
		return true
	}
	return false
}

// indexKeys are the exact values a rule is indexed by, lowercased; "" is a field it has no exact value
// for.
type indexKeys struct {
	packageName, distroName, ecosystem, cpeVendor, cpeProduct string
}

func distroNameOf(d *distro.Distro) string {
	if d == nil {
		return ""
	}
	return d.Name()
}

// searchMatch is a rule reached by a search: what the rule replaces, with the templates to expand.
type searchMatch struct {
	row    SearchRule
	order  int                    // read order, which decides search order
	byRule vulnerability.Criteria // marks the searches the rule adds

	channel            template
	distroName         template
	distroVersion      template
	distroLabelVersion template
	packageName        template
	ecosystem          template
	cpeVendor          template
	cpeProduct         template
}

// appliesTo is false for a rule limited to the other kind of search than s (see
// SearchRule.MatchUpstreamSearch).
func (m *searchMatch) appliesTo(s searchSubject) bool {
	return m.row.MatchUpstreamSearch == nil || *m.row.MatchUpstreamSearch == s.upstream
}

// compiledRule is a rule as it is filed: under its exact values, then down a chain of its remaining
// patterns, ending at its match.
type compiledRule struct {
	keys     indexKeys
	patterns []*regexMatch
	match    *searchMatch
}

func compileSearchRule(row SearchRule) (*compiledRule, error) {
	r := &compiledRule{match: &searchMatch{row: row, byRule: search.ByRule(row.Priority)}}
	// the names a replacement may reference: matched fields and the named groups of match patterns
	names := map[string]struct{}{}

	for _, p := range []struct {
		matchType
		pattern string
		negate  bool
		key     *string // where an exact value is indexed; nil when it is not
	}{
		{distroName, row.MatchDistroName, false, &r.keys.distroName},
		{distroVersion, row.MatchDistroVersion, false, nil},
		{distroChannel, row.MatchDistroChannel, false, nil},
		{ecosystem, row.MatchEcosystem, false, &r.keys.ecosystem},
		{packageName, row.MatchPackageName, false, &r.keys.packageName},
		{packageVersion, row.MatchPackageVersion, false, nil},
		{cpeVendor, row.MatchCPEVendor, false, &r.keys.cpeVendor},
		{cpeProduct, row.MatchCPEProduct, false, &r.keys.cpeProduct},
		// excludes last, so rules differing only by one share the patterns before it
		{packageName, row.ExcludePackageName, true, nil},
		{packageVersion, row.ExcludePackageVersion, true, nil},
		{cpeVendor, row.ExcludeCPEVendor, true, nil},
		{cpeProduct, row.ExcludeCPEProduct, true, nil},
	} {
		if p.pattern == "" {
			continue
		}
		re, literal, err := compilePattern(p.pattern)
		if err != nil {
			return nil, err
		}
		if !p.negate {
			names[string(p.matchType)] = struct{}{}
			if err := addGroupNames(names, re); err != nil {
				return nil, err
			}
		}
		if literal != "" && p.key != nil {
			*p.key = strings.ToLower(literal)
			continue
		}
		groups := slices.ContainsFunc(re.SubexpNames(), func(n string) bool { return n != "" })
		r.patterns = append(r.patterns, &regexMatch{matchType: p.matchType, negate: p.negate, regex: re, groups: groups})
	}

	if err := validateSearchRule(row, r.keys); err != nil {
		return nil, err
	}
	if err := r.match.compileReplacements(names); err != nil {
		return nil, err
	}
	return r, nil
}

// compileReplacements parses the rule's replacement templates, which may reference names.
func (m *searchMatch) compileReplacements(names map[string]struct{}) error {
	row := m.row
	for _, t := range []struct {
		column string
		value  *string
		dst    *template
	}{
		{"replacement channel", row.ReplacementChannel, &m.channel},
		{"replacement distro name", row.ReplacementDistroName, &m.distroName},
		{"replacement distro version", row.ReplacementDistroVersion, &m.distroVersion},
		{"replacement distro label version", row.ReplacementDistroLabelVersion, &m.distroLabelVersion},
		{"replacement package name", &row.ReplacementPackageName, &m.packageName},
		{"replacement ecosystem", &row.ReplacementEcosystem, &m.ecosystem},
		{"replacement CPE vendor", &row.ReplacementCPEVendor, &m.cpeVendor},
		{"replacement CPE product", &row.ReplacementCPEProduct, &m.cpeProduct},
	} {
		if t.value == nil {
			continue
		}
		parsed := parseTemplate(*t.value)
		if err := parsed.validate(names); err != nil {
			return fmt.Errorf("search rule %s %q: %w", t.column, *t.value, err)
		}
		*t.dst = parsed
	}
	return nil
}

func validateSearchRule(row SearchRule, keys indexKeys) error {
	hasReplacement := row.hasPackageSearchReplacement() || row.hasCPEReplacement()
	switch {
	case keys == indexKeys{}:
		return fmt.Errorf("search rule must have an exact (non-regex) package name, distro name, ecosystem, CPE vendor or CPE product")
	case row.MatchEcosystem == "" && row.MatchPackageName == "" && row.MatchPackageVersion == "" &&
		row.MatchCPEVendor == "" && row.MatchCPEProduct == "":
		return fmt.Errorf("search rule must match an ecosystem, package name, package version or CPE")
	}
	switch row.Action {
	case SearchRuleAdd, SearchRuleReplace:
		if !hasReplacement {
			return fmt.Errorf("search rule with action %q must have a replacement", row.Action)
		}
	case SearchRuleDrop:
		if hasReplacement {
			return fmt.Errorf("search rule with action %q cannot have a replacement", row.Action)
		}
		return nil
	case "":
		return errors.New("search rule must have an action")
	default:
		return fmt.Errorf("search rule has an unknown action %q (want %q, %q or %q)", row.Action, SearchRuleAdd, SearchRuleReplace, SearchRuleDrop)
	}
	return validateReplacements(row, keys)
}

// validateReplacements rejects replacements the rule's patterns do not scope, or that cannot apply
// together.
func validateReplacements(row SearchRule, keys indexKeys) error {
	switch {
	case row.ReplacementPackageName != "" && row.MatchPackageName == "":
		return fmt.Errorf("search rule with a replacement package name must have a package name pattern")
	case row.ReplacementEcosystem != "" && row.MatchEcosystem == "":
		return fmt.Errorf("search rule with a replacement ecosystem must have an ecosystem pattern")
	case row.ReplacementChannel != nil && keys.distroName == "":
		return fmt.Errorf("search rule with a channel substitution must have an exact distro name")
	case row.ReplacementDistroVersion != nil && row.ReplacementDistroName == nil && keys.distroName == "":
		return fmt.Errorf("search rule with a distro version substitution must have a distro name substitution or an exact distro name")
	case row.isOSLessSearch() && row.ReplacementChannel != nil:
		return fmt.Errorf("search rule searching no OS cannot have a channel substitution")
	case row.ReplacementDistroLabelVersion != nil && row.ReplacementDistroName == nil && keys.distroName == "":
		return fmt.Errorf("search rule with a distro label version substitution must have a distro name substitution or an exact distro name")
	case row.isOSLessSearch() && row.ReplacementDistroVersion != nil:
		return fmt.Errorf("search rule searching no OS cannot have a distro version substitution")
	case row.isOSLessSearch() && row.ReplacementDistroLabelVersion != nil:
		return fmt.Errorf("search rule searching no OS cannot have a distro label version substitution")
	case row.hasCPEReplacement() && row.MatchCPEVendor == "" && row.MatchCPEProduct == "":
		return fmt.Errorf("search rule with a CPE substitution must have a CPE vendor or product pattern")
	case row.hasCPEReplacement() && row.hasPackageSearchReplacement():
		return fmt.Errorf("search rule with a CPE substitution cannot have an OS, package name or ecosystem substitution")
	}
	return nil
}

// compilePattern returns the pattern as an anchored, case-insensitive regex, and its value when it has
// no regex syntax. The anchoring group is non-capturing, so a top-level `|` is anchored on every branch.
// Patterns come from the DB, so a bad one is an error, never a panic.
func compilePattern(pattern string) (re *regexp.Regexp, literal string, err error) {
	if c, ok := compiledPatterns.Load(pattern); ok {
		c := c.(compiledPattern)
		return c.re, c.literal, c.err
	}
	var c compiledPattern
	c.re, c.literal, c.err = compileUncachedPattern(pattern)
	compiledPatterns.Store(pattern, c)
	return c.re, c.literal, c.err
}

// compiledPatterns caches compilePattern by pattern: a DB's rules share patterns, and a rule compiles
// once to validate it and again to index it.
// ponytail: unbounded, but it holds only the patterns of the DBs a process loads.
var compiledPatterns sync.Map

type compiledPattern struct {
	re      *regexp.Regexp
	literal string
	err     error
}

func compileUncachedPattern(pattern string) (*regexp.Regexp, string, error) {
	// the pattern must parse on its own, or it could close the anchoring group (`a)|(?:b`)
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, "", invalidPatternError(pattern, err)
	}
	re, err := regexp.Compile("(?i)^(?:" + pattern + ")$")
	if err != nil {
		return nil, "", invalidPatternError(pattern, err)
	}
	var literal string
	if parsed.Op == syntax.OpLiteral && parsed.Flags&syntax.FoldCase == 0 {
		literal = string(parsed.Rune)
	}
	return re, literal, nil
}

// invalidPatternError abbreviates the pattern, which regexp errors repeat whole, as it is logged.
func invalidPatternError(pattern string, err error) error {
	var serr *syntax.Error
	if errors.As(err, &serr) {
		err = &syntax.Error{Code: serr.Code, Expr: abbreviate(serr.Expr)}
	}
	return fmt.Errorf("search rule has an invalid pattern %q: %w", abbreviate(pattern), err)
}

func abbreviate(s string) string {
	const maxLen = 80
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// addGroupNames adds re's named groups to names, rejecting one that shadows a match type or that
// another pattern defines. A name may repeat within one pattern, across alternation branches.
func addGroupNames(names map[string]struct{}, re *regexp.Regexp) error {
	own := map[string]struct{}{}
	for _, n := range re.SubexpNames() {
		if _, ok := own[n]; ok || n == "" {
			continue
		}
		own[n] = struct{}{}
		if matchType(n).isValid() {
			return fmt.Errorf("search rule group %q shadows the field of that name", n)
		}
		if _, ok := names[n]; ok {
			return fmt.Errorf("search rule defines group %q in more than one pattern", n)
		}
		names[n] = struct{}{}
	}
	return nil
}

// regexMatch is a node of the index below the exact values: one pattern, which rules with the same
// pattern at the same place share. A search reaching it that matches reaches its matches and next.
type regexMatch struct {
	matchType
	negate  bool // an Exclude* column: the search passes when the pattern does not match
	regex   *regexp.Regexp
	groups  bool // the pattern has named groups
	next    []*regexMatch
	matches []*searchMatch // rules ending here
}

// sameAs is true for a regexMatch of the same match type, negation and pattern.
func (rm *regexMatch) sameAs(other *regexMatch) bool {
	return rm.matchType == other.matchType && rm.negate == other.negate && rm.regex.String() == other.regex.String()
}

func (rm *regexMatch) walk(s searchSubject, captures []capture, out []matchedRule) []matchedRule {
	captures, ok := rm.match(s, captures)
	if !ok {
		return out
	}
	for _, m := range rm.matches {
		if m.appliesTo(s) {
			out = append(out, matchedRule{rule: m, captures: captures})
		}
	}
	for _, next := range rm.next {
		out = next.walk(s, captures, out)
	}
	return out
}

// match returns captures plus what the node captured from the first of its values that matches (see
// capture). A negated node instead rejects a search whose value matches, and passes one that does not
// state it, capturing nothing.
func (rm *regexMatch) match(s searchSubject, captures []capture) ([]capture, bool) {
	values, n := rm.values(s)
	for i, v := range values[:n] {
		var groups []string
		if rm.groups {
			if groups = rm.regex.FindStringSubmatch(v); groups == nil {
				continue
			}
		} else if !rm.regex.MatchString(v) {
			continue
		}
		if rm.negate {
			return nil, false
		}
		return rm.capture(captures, i, v, groups), true
	}
	return captures, rm.negate
}

// capture returns captures plus the node's named groups, and the matched value as its match type
// unless it is the first value, which a reference to the match type resolves to anyway. It copies
// captures, which sibling nodes share, only when it adds to them.
func (rm *regexMatch) capture(captures []capture, i int, v string, groups []string) []capture {
	if i == 0 && groups == nil {
		return captures
	}
	out := slices.Clip(captures)
	if i > 0 {
		out = append(out, capture{name: string(rm.matchType), value: v})
	}
	own := len(out)
	for j, name := range rm.regex.SubexpNames() {
		if name == "" {
			continue
		}
		// a name repeated across alternation branches binds the branch that matched
		k := slices.IndexFunc(out[own:], func(c capture) bool { return c.name == name })
		switch {
		case k < 0:
			out = append(out, capture{name: name, value: groups[j]})
		case groups[j] != "":
			out[own+k].value = groups[j]
		}
	}
	return out
}

// capture is a value a pattern captured: a named group, or the matched value under its match type.
type capture struct {
	name, value string
}

// matchedRule is a rule a search reached, with what its patterns captured.
type matchedRule struct {
	rule     *searchMatch
	captures []capture
}

// expand resolves t's references against the captures, then the search's own field values (which an
// exact, indexed value is not captured as).
func (m matchedRule) expand(t template, s searchSubject) string {
	return t.expand(func(name string) string {
		for _, c := range m.captures {
			if c.name == name {
				return c.value
			}
		}
		if t := matchType(name); t.isValid() {
			return t.firstValue(s)
		}
		return ""
	})
}

// overlayDistro returns the OS the rule searches instead of the searched one: the searched OS with
// the rule's channel, version and/or label version, and/or another OS name; ok is false to keep it.
// osLess is true for a rule searching the rows of no OS. A search with no OS can only gain an OS name,
// version-less and label-less unless the rule names them.
func (m matchedRule) overlayDistro(s searchSubject) (overlay distro.Distro, ok, osLess bool) {
	row := m.rule.row
	if row.isOSLessSearch() {
		return overlay, false, true
	}
	if row.ReplacementChannel == nil && row.ReplacementDistroName == nil && row.ReplacementDistroVersion == nil &&
		row.ReplacementDistroLabelVersion == nil {
		return overlay, false, false
	}

	var name string
	if row.ReplacementDistroName != nil {
		// a template whose groups matched empty names no OS
		if name = m.expand(m.rule.distroName, s); name == "" {
			return overlay, false, false
		}
	}

	var label string
	if row.ReplacementDistroLabelVersion != nil {
		label = m.expand(m.rule.distroLabelVersion, s)
	}

	if s.distro == nil {
		if name == "" {
			return overlay, false, false
		}
		var version string
		if row.ReplacementDistroVersion != nil {
			version = m.expand(m.rule.distroVersion, s)
		}
		return *distro.New(distro.TypeFromID(name), version, label), true, false
	}

	switch {
	case row.ReplacementDistroVersion != nil:
		// an empty expansion selects the version-less rows
		t := s.distro.Type
		if name != "" {
			t = distro.TypeFromID(name)
		}
		overlay = *distro.New(t, m.expand(m.rule.distroVersion, s), "")
	case name != "":
		overlay = *distro.New(distro.TypeFromID(name), s.distro.Version, "")
	default:
		overlay = *s.distro
		overlay.Channels = nil
	}
	if row.ReplacementDistroLabelVersion != nil {
		// an empty expansion searches by the OS version alone
		overlay.Codename = label
	}
	if row.ReplacementChannel != nil {
		// an empty expansion selects the channel-less rows
		if channel := m.expand(m.rule.channel, s); channel != "" {
			overlay.Channels = []string{channel}
		}
	}
	return overlay, true, false
}

type template []templatePart

// templatePart is a literal, or a reference when ref is set.
type templatePart struct {
	literal string
	ref     string
}

// parseTemplate parses a replacement as regexp.Regexp.Expand does: `$name` or `${name}` references a
// group, where a name is a run of letters, digits and underscores (so `$ax` is the group named "ax";
// write `${a}x`), and `$$` is a literal `$`. A `$` that starts no reference is literal.
func parseTemplate(s string) template {
	var out template
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			out = append(out, templatePart{literal: lit.String()})
			lit.Reset()
		}
	}
	for len(s) > 0 {
		i := strings.IndexByte(s, '$')
		if i < 0 {
			lit.WriteString(s)
			break
		}
		lit.WriteString(s[:i])
		s = s[i:]
		if len(s) > 1 && s[1] == '$' {
			lit.WriteByte('$')
			s = s[2:]
			continue
		}
		ref, rest, ok := extractRef(s)
		if !ok {
			lit.WriteByte('$')
			s = s[1:]
			continue
		}
		flush()
		out = append(out, templatePart{ref: ref})
		s = rest
	}
	flush()
	return out
}

// extractRef parses the reference at the start of s, which begins with `$`.
func extractRef(s string) (ref, rest string, ok bool) {
	s = s[1:]
	braced := len(s) > 0 && s[0] == '{'
	if braced {
		s = s[1:]
	}
	i := 0
	for i < len(s) && isRefByte(s[i]) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	ref, rest = s[:i], s[i:]
	if braced {
		if len(rest) == 0 || rest[0] != '}' {
			return "", "", false
		}
		rest = rest[1:]
	}
	return ref, rest, true
}

func isRefByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// validate rejects references that can never resolve: positional ones, and names that are neither a
// matched field nor a named group of a match pattern.
func (t template) validate(names map[string]struct{}) error {
	for _, p := range t {
		if p.ref == "" {
			continue
		}
		if _, err := strconv.Atoi(p.ref); err == nil {
			return fmt.Errorf("positional reference $%s is not supported; use a named group", p.ref)
		}
		if _, ok := names[p.ref]; !ok {
			return fmt.Errorf("reference ${%s} names no group of a match pattern nor a matched field", p.ref)
		}
	}
	return nil
}

// expand resolves references with lookup.
func (t template) expand(lookup func(name string) string) string {
	switch {
	case len(t) == 0:
		return ""
	case len(t) == 1 && t[0].ref == "":
		return t[0].literal
	case len(t) == 1:
		return lookup(t[0].ref)
	}
	var sb strings.Builder
	for _, p := range t {
		if p.ref == "" {
			sb.WriteString(p.literal)
		} else {
			sb.WriteString(lookup(p.ref))
		}
	}
	return sb.String()
}
