package v6

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
// OS: for a CPE search, the NVD rows.
func (o SearchRule) isOSLessSearch() bool {
	return o.ReplacementDistroName != nil && *o.ReplacementDistroName == ""
}

// searchSubject is what one search states about the package it searches for.
type searchSubject struct {
	name      string
	version   string
	ecosystem string
	distro    *distro.Distro
}

// matchType is which of the search's values a Match*/Exclude* column matches. A match captures the
// matched value under its name (e.g. ${package_name}), which no pattern may define a group of.
type matchType string

const (
	distroName     matchType = "distro_name"
	distroVersion  matchType = "distro_version"
	ecosystem      matchType = "ecosystem"
	packageName    matchType = "package_name"
	packageVersion matchType = "package_version"
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
	case ecosystem:
		values[0] = s.ecosystem
	case packageName:
		values[0] = s.name
	case packageVersion:
		values[0] = s.version
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
	case distroName, distroVersion, ecosystem, packageName, packageVersion:
		return true
	}
	return false
}

// indexKeys are the exact values a rule is indexed by, lowercased; "" is a field it has no exact value
// for.
type indexKeys struct {
	packageName, distroName, ecosystem string
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

	channel     template
	distroName  template
	packageName template
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
		{ecosystem, row.MatchEcosystem, false, &r.keys.ecosystem},
		{packageName, row.MatchPackageName, false, &r.keys.packageName},
		{packageVersion, row.MatchPackageVersion, false, nil},
		// excludes last, so rules differing only by one share the patterns before it
		{packageName, row.ExcludePackageName, true, nil},
		{packageVersion, row.ExcludePackageVersion, true, nil},
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

	for _, t := range []struct {
		column string
		value  *string
		dst    *template
	}{
		{"replacement channel", row.ReplacementChannel, &r.match.channel},
		{"replacement distro name", row.ReplacementDistroName, &r.match.distroName},
		{"replacement package name", &row.ReplacementPackageName, &r.match.packageName},
	} {
		if t.value == nil {
			continue
		}
		parsed := parseTemplate(*t.value)
		if err := parsed.validate(names); err != nil {
			return nil, fmt.Errorf("search rule %s %q: %w", t.column, *t.value, err)
		}
		*t.dst = parsed
	}

	return r, nil
}

func validateSearchRule(row SearchRule, keys indexKeys) error {
	switch {
	case keys == indexKeys{}:
		return fmt.Errorf("search rule must have an exact (non-regex) package name, distro name or ecosystem")
	case row.MatchEcosystem == "" && row.MatchPackageName == "" && row.MatchPackageVersion == "":
		return fmt.Errorf("search rule must match an ecosystem, package name or package version")
	case row.ReplacementPackageName != "" && row.MatchPackageName == "":
		return fmt.Errorf("search rule with a replacement package name must have a package name pattern")
	case row.ReplacementChannel != nil && keys.distroName == "":
		return fmt.Errorf("search rule with a channel substitution must have an exact distro name")
	case row.ReplacementChannel == nil && row.ReplacementDistroName == nil && row.ReplacementPackageName == "":
		return fmt.Errorf("search rule must have a replacement")
	case row.isOSLessSearch() && row.ReplacementChannel != nil:
		return fmt.Errorf("search rule searching no OS cannot have a channel substitution")
	}
	return nil
}

// compilePattern returns the pattern as an anchored, case-insensitive regex, and its value when it has
// no regex syntax. The anchoring group is non-capturing, so a top-level `|` is anchored on every branch.
func compilePattern(pattern string) (re *regexp.Regexp, literal string, err error) {
	anchored := "^(?:" + pattern + ")$"
	re, err = regexp.Compile(anchored)
	if err != nil {
		return nil, "", fmt.Errorf("search rule has an invalid pattern %q: %w", pattern, err)
	}
	if prefix, complete := re.LiteralPrefix(); complete {
		literal = prefix
	}
	return regexp.MustCompile("(?i)" + anchored), literal, nil
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
		out = append(out, matchedRule{rule: m, captures: captures})
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
// the rule's channel, and/or another OS name; ok is false to keep it. osLess is true for a rule
// searching the rows of no OS. A search with no OS can only gain a version-less OS name.
func (m matchedRule) overlayDistro(s searchSubject) (overlay distro.Distro, ok, osLess bool) {
	row := m.rule.row
	if row.isOSLessSearch() {
		return overlay, false, true
	}
	if row.ReplacementChannel == nil && row.ReplacementDistroName == nil {
		return overlay, false, false
	}

	var name string
	if row.ReplacementDistroName != nil {
		// a template whose groups matched empty names no OS
		if name = m.expand(m.rule.distroName, s); name == "" {
			return overlay, false, false
		}
	}

	if s.distro == nil {
		if name == "" {
			return overlay, false, false
		}
		return *distro.New(distro.TypeFromID(name), "", ""), true, false
	}

	if name != "" {
		overlay = *distro.New(distro.TypeFromID(name), s.distro.Version, "")
	} else {
		overlay = *s.distro
		overlay.Channels = nil
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
