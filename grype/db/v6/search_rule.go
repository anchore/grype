package v6

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
)

// This file implements the evaluation semantics for SearchRule rows: one rule model that rewrites
// how an individual vulnerability search is performed — which names are searched and which
// OperatingSystem rows (a channel and/or a different OS name) are queried — via regex predicates
// and $N-template substitutions.
//
// Rules are evaluated against the parsed searchQuery rather than against the raw criteria, so they
// read the same typed specifiers the store is about to be queried with and a rewrite is an edit to
// those specifiers rather than a rebuild of the criteria.
//
// A predicate whose subject the query does not carry cannot match. Distro queries carry OS
// specifiers + package name (+ version for version-filtered searches) but no ecosystem, so rules
// meant for them (e.g. the rapidfort release-stream routing) must not constrain by ecosystem;
// ecosystem queries carry ecosystem + package name + version but no OS, so rules meant for them
// (e.g. echo's vendor-data overlay) must not constrain by distro. This is what lets one rule set
// serve both incoming query shapes.
//
// Rules are ranked, not ordered: of the rules matching a query (and applying to the reading
// client's DB schema), only those at the highest Priority apply, and rules tied at that priority
// all apply together. Resolution is therefore independent of the order rules are read from the
// DB, and precedence between rules is stated by the winner's priority rather than by every loser
// having to exclude the winner's markers through its own predicates. OS-scoped data policies are
// exempt from that ranking and always apply (see highestPriority).
//
// Every pattern is fully anchored (see anchorPattern): it must describe the whole subject, so partial
// matching is spelled with an explicit `.*`. Use `.*?` for a leading wildcard when a capture group
// follows it, so $N expands from the first occurrence of the marker rather than the last.

// anchorPattern wraps a rule pattern so it must describe the entire subject. Rule patterns are fully
// anchored by design: an unanchored `rf` would select every package with `rf` anywhere in its name,
// and anchoring is also what lets a pattern be decomposed into an exact match, a prefix, or a
// required substring (see patternShape) rather than always being run as a regex. The group is
// non-capturing so the author's group numbers survive and $N references in ReplacementChannel and
// ReplacementPackageName still resolve; without it a pattern containing a top-level `|` would anchor
// only its first and last branches.
func anchorPattern(p string) string {
	return "^(?:" + p + ")$"
}

// Validate returns why the row is not a legal rule, or nil. This is the single definition of
// "legal rule shape", shared by the compile path (warn-and-skip) and the DB write path (reject;
// see SearchRule.BeforeCreate) so the two can never drift apart.
func (o SearchRule) Validate() error {
	if o.ReplacementChannel == nil && o.ReplacementDistroName == nil && o.ReplacementPackageName == "" && o.IncludeBaseDistro == nil {
		return fmt.Errorf("search rule must have at least one substitution")
	}
	if o.ReplacementPackageName != "" && o.MatchPackageName == "" {
		return fmt.Errorf("search rule with a replacement package name must have a package name pattern")
	}
	if o.MatchDistroName == "" && o.ReplacementChannel != nil {
		// a channel is meaningful only relative to a specific OS's rows; without a distro
		// predicate the rule would rewrite the channel of every distro query it matched
		return fmt.Errorf("search rule with a channel substitution must have a distro name to match")
	}
	if o.MatchPackageName == "" && o.MatchPackageVersion == "" && !o.dataPolicyOnly() {
		// only an OS-scoped data policy rule (IncludeBaseDistro as the sole substitution) may
		// omit package predicates; any other predicate-free rule would apply to every query
		return fmt.Errorf("search rule must have at least one package predicate")
	}
	for _, p := range []string{o.MatchDistroVersion, o.MatchPackageName, o.ExcludePackageName, o.MatchPackageVersion, o.ExcludePackageVersion} {
		if p == "" {
			continue
		}
		// compile the anchored form, so a pattern is rejected on the same terms it will be evaluated on
		if _, err := regexp.Compile(anchorPattern(p)); err != nil {
			return fmt.Errorf("search rule has an invalid pattern %q: %w", p, err)
		}
	}
	return nil
}

// dataPolicyOnly marks an OS-scoped rule whose only output is IncludeBaseDistro: it is the one rule
// shape allowed to match without a package predicate (name/distro substitutions applying to every
// package of an OS would be a data error, but a data policy for an OS is exactly per-OS by
// nature).
func (o SearchRule) dataPolicyOnly() bool {
	return o.IncludeBaseDistro != nil && o.MatchDistroName != "" &&
		o.ReplacementChannel == nil && o.ReplacementDistroName == nil && o.ReplacementPackageName == ""
}

// includeBaseDistro indicates whether the queried OS rows are searched in addition to the data this
// rule selects (nil expresses no preference, which resolves to "include": a rule claiming its data
// is the complete picture for the package must say so).
func (o SearchRule) includeBaseDistro() bool {
	return o.IncludeBaseDistro == nil || *o.IncludeBaseDistro
}

// compiledSearchRule is the compiled form of a SearchRule row: each pattern as an anchored regex,
// paired with the cheap necessary condition derived from it (see patternShape) that decides whether
// the regex needs to run at all.
type compiledSearchRule struct {
	row SearchRule

	// ord is the rule's position in the set as read, so candidates gathered from several index
	// buckets can be restored to that order (see searchRuleIndex.candidates)
	ord int

	distroVersion     *regexp.Regexp
	pkgName           *regexp.Regexp
	excludePkgName    *regexp.Regexp
	pkgVersion        *regexp.Regexp
	excludePkgVersion *regexp.Regexp

	distroVersionShape     patternShape
	pkgNameShape           patternShape
	excludePkgNameShape    patternShape
	pkgVersionShape        patternShape
	excludePkgVersionShape patternShape
}

// compileSearchRules compiles rows into evaluable rules, skipping invalid rows (warn-and-continue:
// a bad rule should never take down matching). Order is irrelevant — the applicable rules are
// selected by priority — so the returned slice preserves the input order rather than imposing one.
func compileSearchRules(rows []SearchRule) []*compiledSearchRule {
	var rules []*compiledSearchRule
	for _, row := range rows {
		if err := row.Validate(); err != nil {
			log.WithFields("error", err, "distro", row.MatchDistroName, "ecosystem", row.MatchEcosystem).Warn("skipping invalid search rule")
			continue
		}

		rule := &compiledSearchRule{row: row}
		for _, pc := range []struct {
			pattern string
			dst     **regexp.Regexp
			shape   *patternShape
		}{
			{row.MatchDistroVersion, &rule.distroVersion, &rule.distroVersionShape},
			{row.MatchPackageName, &rule.pkgName, &rule.pkgNameShape},
			{row.ExcludePackageName, &rule.excludePkgName, &rule.excludePkgNameShape},
			{row.MatchPackageVersion, &rule.pkgVersion, &rule.pkgVersionShape},
			{row.ExcludePackageVersion, &rule.excludePkgVersion, &rule.excludePkgVersionShape},
		} {
			if pc.pattern == "" {
				continue
			}
			anchored := anchorPattern(pc.pattern)
			*pc.dst = regexp.MustCompile(anchored) // Validate compiled these already
			*pc.shape = newPatternShape(anchored)
		}

		rules = append(rules, rule)
	}
	return rules
}

// hasDistroPredicate indicates whether the rule constrains which OS it applies to, which decides both
// whether an OS-less query can match it and whether a substitution rewrites every queried OS or only
// the ones it named.
func (r *compiledSearchRule) hasDistroPredicate() bool {
	return r.row.MatchDistroName != "" || r.distroVersion != nil
}

// matches indicates whether the rule applies to the given query. Every set predicate must match,
// and a predicate whose subject the query did not provide fails the rule — matching occurs on what
// the query carries, nothing is assumed about what it left unsaid. Exclude* predicates are the one
// exception in spirit: they only reject when their subject is present and matches (an absent subject
// cannot prove the exclusion).
func (r *compiledSearchRule) matches(q *searchQuery) bool {
	if r.hasDistroPredicate() && !r.matchesAnyOS(q.osSpecs) {
		return false
	}
	if r.row.MatchEcosystem != "" && !strings.EqualFold(r.row.MatchEcosystem, string(q.pkgType)) {
		return false
	}

	pkgName := q.packageName()
	if r.pkgName != nil && (pkgName == "" || !matchPattern(r.pkgName, r.pkgNameShape, pkgName)) {
		return false
	}
	if r.excludePkgName != nil && pkgName != "" && matchPattern(r.excludePkgName, r.excludePkgNameShape, pkgName) {
		return false
	}
	if r.pkgVersion != nil && (q.version == "" || !matchPattern(r.pkgVersion, r.pkgVersionShape, q.version)) {
		return false
	}
	if r.excludePkgVersion != nil && q.version != "" && matchPattern(r.excludePkgVersion, r.excludePkgVersionShape, q.version) {
		return false
	}
	// a substitution rule with no package predicates is rejected at creation time, but guard
	// against hand-crafted rules that would otherwise apply to every query; OS-scoped data
	// policy rules (see SearchRule.dataPolicyOnly) are the one shape allowed to match
	// predicate-free
	return r.pkgName != nil || r.pkgVersion != nil || r.row.dataPolicyOnly()
}

func (r *compiledSearchRule) matchesAnyOS(specs OSSpecifiers) bool {
	for _, s := range specs {
		if r.matchesOS(s) {
			return true
		}
	}
	return false
}

// matchesOS indicates whether the rule's distro predicates match one queried OS specifier. The
// "any OS" and "no OS" specifiers are the absence of a named OS rather than an OS whose name is
// empty, so no distro predicate can match them.
func (r *compiledSearchRule) matchesOS(spec *OSSpecifier) bool {
	if spec == nil || *spec == *NoOSSpecified {
		return false
	}
	if r.row.MatchDistroName != "" && !strings.EqualFold(r.row.MatchDistroName, spec.Name) {
		return false
	}
	if r.distroVersion != nil && !r.matchesOSVersion(spec) {
		return false
	}
	return true
}

// matchesOSVersion mirrors OSSpecifier.matchesVersionPattern, which is how the OS specifier
// overrides already define what a distro version pattern means for a specifier: match the joined
// version, or failing that the version label.
func (r *compiledSearchRule) matchesOSVersion(spec *OSSpecifier) bool {
	if matchPattern(r.distroVersion, r.distroVersionShape, spec.version()) {
		return true
	}
	return spec.LabelVersion != "" && matchPattern(r.distroVersion, r.distroVersionShape, spec.LabelVersion)
}

// expandName resolves $N references in the replacement package name against the name pattern's
// capture groups for the given candidate, or "" when the pattern does not match.
func (r *compiledSearchRule) expandName(candidate string) string {
	m := r.pkgName.FindStringSubmatchIndex(candidate)
	if m == nil {
		return ""
	}
	return string(r.pkgName.ExpandString(nil, r.row.ReplacementPackageName, candidate, m))
}

// expandChannel resolves $N references in the replacement channel against the package version
// pattern's capture groups (e.g. pattern `.*?\.fc(\d+).*` + channel "fc$1" -> "fc43").
func (r *compiledSearchRule) expandChannel(version string) string {
	channel := *r.row.ReplacementChannel
	if r.pkgVersion == nil || version == "" || !strings.Contains(channel, "$") {
		return channel
	}
	m := r.pkgVersion.FindStringSubmatchIndex(version)
	if m == nil {
		return channel
	}
	return string(r.pkgVersion.ExpandString(nil, channel, version, m))
}

// applySearchRules is the single chokepoint that passes one parsed query through the search rules,
// returning the queries to actually run in its place. Callers run every returned query and union the
// results — which is what lets a vendor's data live under its own OS name (e.g. echo next to debian's
// OS-less ecosystem rows) and be addressed separately from the base data.
//
// Of the rules that match, only those at the highest priority are applied; rules tied at that
// priority all apply together. That selection is made once, across all matched rules, so a
// higher-priority rule also suppresses a lower-priority rule's name substitutions:
//
//   - OS substitutions rewrite the query's OS specifiers: every applied rule contributes its overlay
//     OS identity (a channel selected from version/name markers, or another vendor's OS name), and
//     the queried OS is kept alongside them unless every applied substitution rule sets
//     IncludeBaseDistro false — that is, unless the data those rules select is the complete picture
//     for the package, leaving nothing for the base rows to add. A query with no OS keeps its
//     original (OS-less) search under the same condition and gains one additional query per overlay —
//     the two cannot share one query because a specific OS cannot be combined with the "no OS"
//     specifier (see packageStore.handleOSOptions).
//   - name substitutions accumulate: every applied rule with a ReplacementPackageName contributes an
//     expanded name, each producing an additional query with the package name replaced; derived names
//     are not re-expanded.
//   - IncludeBaseDistro false additionally tells matchers not to fall back to the ecosystem's
//     upstream data; that search is theirs to make, so it is served by
//     vulnerabilityProvider.SearchRules rather than by rewriting the query.
func applySearchRules(rules *searchRuleIndex, q *searchQuery) []*searchQuery {
	if rules == nil || len(rules.rules) == 0 {
		return []*searchQuery{q}
	}

	matched := highestPriority(matchingRules(rules, q))
	if len(matched) == 0 {
		return []*searchQuery{q}
	}

	// resolve the base queries: the original query with any OS substitutions applied
	base := resolveOSQueries(matched, q)

	// fan each base query out across any additional names
	names := resolveAdditionalNames(matched, q)
	if len(names) == 0 {
		return dropDuplicateCPESearches(base)
	}

	out := make([]*searchQuery, 0, len(base)*(1+len(names)))
	for _, sq := range base {
		out = append(out, sq)
		for _, n := range names {
			out = append(out, sq.withPackageName(n))
		}
	}
	return dropDuplicateCPESearches(out)
}

// dropDuplicateCPESearches leaves the CPE specifier on the first query alone. Rules never rewrite the
// CPE dimension, so every additional query they produce would search exactly the same CPEs; those
// duplicate results were only ever collapsed downstream (result.Set is keyed by vulnerability ID).
// Expressing it on the queries rather than at the call site is what lets them all be run as one flat
// list — fetchAndProcessCPEs no-ops on a nil CPE specifier.
func dropDuplicateCPESearches(queries []*searchQuery) []*searchQuery {
	for i := 1; i < len(queries); i++ {
		if queries[i].cpeSpec == nil {
			continue
		}
		q := queries[i].clone()
		q.cpeSpec = nil
		queries[i] = q
	}
	return queries
}

// matchingRules returns the rules that apply to the query, in the order they were read. Only the
// index's candidates are evaluated; the stack buffer keeps that gathering allocation-free for any
// realistic rule set.
func matchingRules(idx *searchRuleIndex, q *searchQuery) []*compiledSearchRule {
	var buf [16]*compiledSearchRule
	var matched []*compiledSearchRule
	for _, r := range idx.candidates(q, buf[:0]) {
		if r.matches(q) {
			matched = append(matched, r)
		}
	}
	return matched
}

// highestPriority narrows matched rules to those at the highest priority among them: precedence is
// stated by rank, and rules tied at that priority all apply together.
//
// OS-scoped data policies (see SearchRule.dataPolicyOnly) are outside that contest and always
// apply. Priority decides which substitution describes a package — which channel, OS name, or extra
// names its lookup uses — and a policy rule substitutes nothing, so it has nothing to win or lose
// against one. Ranking it anyway would mean a package matching any stream rule silently left its
// OS's data policy behind (e.g. an rf-marked rapidfort-alpine package would regain the NVD/CPE
// fallback that rapidfort-alpine's curated feed exists to suppress), and the policy would have to
// be restated on every stream rule to survive.
func highestPriority(matched []*compiledSearchRule) []*compiledSearchRule {
	if len(matched) < 2 {
		return matched
	}
	best, ranked := 0, false
	for _, r := range matched {
		if r.row.dataPolicyOnly() {
			continue
		}
		if !ranked || r.row.Priority > best {
			best, ranked = r.row.Priority, true
		}
	}
	out := make([]*compiledSearchRule, 0, len(matched))
	for _, r := range matched {
		if r.row.dataPolicyOnly() || r.row.Priority == best {
			out = append(out, r)
		}
	}
	return out
}

// resolveOSQueries applies the matched rules' OS substitutions to the query, returning the queries to
// run in its place.
func resolveOSQueries(matched []*compiledSearchRule, q *searchQuery) []*searchQuery {
	var substitutions []*compiledSearchRule
	// the base search is kept unless every applied substitution claims its data is the complete
	// picture for the package; one rule reporting its records as fixes-only is reason enough to
	// keep searching the queried OS rows (the same tie-break matcher/internal.IncludeBaseDistro
	// makes over what SearchRules reports)
	includeBase := false
	for _, r := range matched {
		if r.row.ReplacementChannel == nil && r.row.ReplacementDistroName == nil {
			continue
		}
		substitutions = append(substitutions, r)
		if r.row.includeBaseDistro() {
			includeBase = true
		}
	}
	if len(substitutions) == 0 {
		return []*searchQuery{q}
	}

	if q.isOSLess() {
		return resolveOSLessQueries(substitutions, q, includeBase)
	}

	// rewrite the OS specifiers: overlays are unioned into (or, when the rules' data is the complete
	// picture, substituted for) the queried specifiers within the one query
	var resolved []*OSSpecifier
	for _, base := range q.osSpecs {
		var overlays []*OSSpecifier
		for _, r := range substitutions {
			// a rule with distro predicates only rewrites the OS specifiers it matched
			if r.hasDistroPredicate() && !r.matchesOS(base) {
				continue
			}
			overlays = append(overlays, r.overlayFor(base, q.version))
		}

		if includeBase || len(overlays) == 0 {
			// a union rule that resolved to the base itself (e.g. a channel that expanded
			// empty) is deduped below rather than producing the same search twice
			resolved = append(resolved, base)
		}
		resolved = append(resolved, overlays...)
	}

	return []*searchQuery{q.withOSSpecs(dedupeOSSpecifiers(resolved))}
}

// overlayFor builds the OS specifier this rule selects in place of the queried one. The queried
// specifier is copied rather than edited: it is shared with the caller's query, and OSSpecifiers may
// hold the package-level NoOSSpecified sentinel.
func (r *compiledSearchRule) overlayFor(base *OSSpecifier, version string) *OSSpecifier {
	overlay := *base
	if r.row.ReplacementDistroName != nil {
		// the replacement is an OS id, which is not always the distro name it resolves to (e.g. "ol"
		// names oraclelinux), so it is normalized the same way a detected distro would be
		overlay.Name = string(distro.TypeFromID(*r.row.ReplacementDistroName))
		// the codename is intentionally dropped: it is the base vendor's release label, and another
		// vendor's OS records are version-keyed with no codename of their own — so carrying it over
		// adds a codename filter that resolves zero OS rows (see operatingSystemStore.prepareQuery)
		overlay.LabelVersion = ""
	}
	overlay.Channel = ""
	if r.row.ReplacementChannel != nil {
		// an empty (expanded) channel leaves the overlay on the channel-less rows
		overlay.Channel = r.expandChannel(version)
	}
	return &overlay
}

// resolveOSLessQueries handles a query for data stored without an OS: each overlay is searched as an
// additional query, since a specific OS cannot be combined with the "no OS" specifier. Overlays
// resolve version-free — with no queried OS there is no version to carry — which fits vendors whose
// OS identity is rolling (e.g. echo).
func resolveOSLessQueries(substitutions []*compiledSearchRule, q *searchQuery, includeBase bool) []*searchQuery {
	var out []*searchQuery
	if includeBase {
		out = append(out, q)
	}

	var overlays []*OSSpecifier
	for _, r := range substitutions {
		if r.row.ReplacementDistroName == nil {
			continue // a channel substitution needs a queried OS to apply to
		}
		overlays = append(overlays, &OSSpecifier{Name: string(distro.TypeFromID(*r.row.ReplacementDistroName))})
	}
	for _, overlay := range dedupeOSSpecifiers(overlays) {
		out = append(out, q.withOSSpecs(OSSpecifiers{overlay}))
	}
	return out
}

// resolveAdditionalNames returns the extra names the matched rules contribute for the queried
// package name, in first-seen order and excluding the queried name itself.
func resolveAdditionalNames(matched []*compiledSearchRule, q *searchQuery) []string {
	queried := q.packageName()
	if queried == "" || !anyReplacesPackageName(matched) {
		return nil
	}

	var out []string
	seen := map[string]struct{}{queried: {}}
	for _, r := range matched {
		if r.row.ReplacementPackageName == "" {
			continue
		}
		variant := r.expandName(queried)
		if variant == "" {
			continue
		}
		// the queried name was normalized for its ecosystem before rules ran (see
		// searchQueryBuilder.normalizePackageName), so a derived name is too
		variant = name.Normalize(variant, q.pkgType)
		if _, ok := seen[variant]; ok {
			continue
		}
		seen[variant] = struct{}{}
		out = append(out, variant)
	}
	return out
}

func anyReplacesPackageName(matched []*compiledSearchRule) bool {
	for _, r := range matched {
		if r.row.ReplacementPackageName != "" {
			return true
		}
	}
	return false
}

// dedupeScanLimit is the point past which deduplicating OS specifiers is worth a set rather than a
// scan over what has been kept. Resolution nearly always produces one or two specifiers, so the scan
// is the path that runs; the set is here so a rule set that resolves many of them does not go
// quadratic.
const dedupeScanLimit = 8

// dedupeOSSpecifiers drops specifiers that resolved to the same thing — a union rule whose channel
// expanded empty resolves to the base it was applied to, for instance. The "any OS" specifier is nil
// and is always kept, there being nothing to compare it by value.
func dedupeOSSpecifiers(specs []*OSSpecifier) OSSpecifiers {
	out := make(OSSpecifiers, 0, len(specs))

	if len(specs) <= dedupeScanLimit {
		for _, s := range specs {
			if s != nil && containsOSSpecifier(out, *s) {
				continue
			}
			out = append(out, s)
		}
		return out
	}

	seen := make(map[OSSpecifier]struct{}, len(specs))
	for _, s := range specs {
		if s == nil {
			out = append(out, s)
			continue
		}
		if _, ok := seen[*s]; ok {
			continue
		}
		seen[*s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func containsOSSpecifier(specs OSSpecifiers, want OSSpecifier) bool {
	for _, s := range specs {
		if s != nil && *s == want {
			return true
		}
	}
	return false
}
