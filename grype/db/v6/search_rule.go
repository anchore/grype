package v6

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

// This file implements the evaluation semantics for SearchRule rows: one rule model that states how
// an individual vulnerability search should be performed for a package — which names are searched and
// which OperatingSystem rows (a channel and/or a different OS name) are queried — via regex
// predicates and $N-template substitutions.
//
// Rules are evaluated against a parsed searchQuery rather than against raw criteria, so they read the
// same typed specifiers the store is queried with.
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
// having to exclude the winner's markers through its own predicates. Rules that substitute nothing
// are exempt from that ranking and always apply (see highestPriority).
//
// Every pattern is fully anchored (see anchorPattern): it must describe the whole subject, so partial
// matching is spelled with an explicit `.*`. Use `.*?` for a leading wildcard when a capture group
// follows it, so $N expands from the first occurrence of the marker rather than the last.

// anchorPattern wraps a rule pattern so it must describe the entire subject. Rule patterns are fully
// anchored by design: an unanchored `rf` would select every package with `rf` anywhere in its name.
// The group is non-capturing so the author's group numbers survive and $N references in
// ReplacementChannel and ReplacementPackageName still resolve; without it a pattern containing a
// top-level `|` would anchor only its first and last branches.
func anchorPattern(p string) string {
	return "^(?:" + p + ")$"
}

// Validate returns why the row is not a legal rule, or nil. This is the single definition of
// "legal rule shape", shared by the compile path (warn-and-skip) and the DB write path (reject;
// see SearchRule.BeforeCreate) so the two can never drift apart.
func (o SearchRule) Validate() error {
	if o.MatchDistroName == "" && o.MatchEcosystem == "" && o.MatchPackageName == "" && o.MatchPackageVersion == "" {
		// a rule with no predicate would speak for every package there is
		return fmt.Errorf("search rule must have at least one predicate")
	}
	if o.ReplacementPackageName != "" && o.MatchPackageName == "" {
		return fmt.Errorf("search rule with a replacement package name must have a package name pattern")
	}
	if o.MatchDistroName == "" && o.ReplacementChannel != nil {
		// a channel is meaningful only relative to a specific OS's rows; without a distro
		// predicate the rule would rewrite the channel of every distro query it matched
		return fmt.Errorf("search rule with a channel substitution must have a distro name to match")
	}
	if o.MatchPackageName == "" && o.MatchPackageVersion == "" && o.hasSubstitution() {
		// a substitution says how an individual package is searched, so it must name the packages
		// it speaks for; only a rule that substitutes nothing may be scoped to an OS or ecosystem
		// alone (see hasSubstitution)
		return fmt.Errorf("search rule with a substitution must have at least one package predicate")
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

// hasSubstitution indicates whether the rule changes how a matched package is searched, rather than
// only stating something about it. A rule that substitutes nothing is still meaningful: it marks the
// packages a vendor's own data fully describes, which is what suppresses the upstream NVD/CPE search
// a matcher would otherwise make for itself.
//
// A distroless search is not a substitution either (see IsDistrolessSearch): it rewrites no store
// search, it only says those records still count for these packages.
func (o SearchRule) hasSubstitution() bool {
	if o.IsDistrolessSearch() {
		return o.ReplacementChannel != nil || o.ReplacementPackageName != ""
	}
	return o.ReplacementChannel != nil || o.ReplacementDistroName != nil || o.ReplacementPackageName != ""
}

// IsDistrolessSearch indicates whether the rule names the record set stored without an operating
// system -- the CPE-indexed (NVD) rows -- as its OS substitution. That is a non-NULL but empty
// replacement OS name: the absence of an operating system, rather than the absence of a statement
// about one.
//
// No store search can be rewritten to reach those records, since the matchers that want them search
// them for themselves (see the apk matcher's includeNVD). Naming them is how a rule says "and those
// records too" for the packages it matches.
func (o SearchRule) IsDistrolessSearch() bool {
	return o.ReplacementDistroName != nil && *o.ReplacementDistroName == ""
}

// ExpandChannel is the OS channel this rule selects for a package at the given version, with $N
// references resolved against MatchPackageVersion's capture groups (e.g. pattern `.*?\.fc(\d+).*` +
// channel "fc$1" -> "fc43"). It is "" when the rule selects no channel, and also when the template
// expands empty -- which selects the channel-less rows of the OS.
func (o SearchRule) ExpandChannel(pkgVersion string) string {
	if o.ReplacementChannel == nil {
		return ""
	}
	channel := *o.ReplacementChannel
	if !strings.Contains(channel, "$") {
		return channel
	}
	// an unresolvable template leaves the channel as written: the rule matched the package, so its
	// channel is still the answer -- it just has no capture group to fold in
	return expandTemplate(o.MatchPackageVersion, channel, pkgVersion, channel)
}

// ExpandPackageName is the additional name this rule contributes for the given searched name, with
// $N references resolved against MatchPackageName's capture groups. It is "" when the rule adds no
// name, or when the pattern does not describe this name -- an unresolved template is no name at all.
func (o SearchRule) ExpandPackageName(pkgName string) string {
	if o.ReplacementPackageName == "" {
		return ""
	}
	return expandTemplate(o.MatchPackageName, o.ReplacementPackageName, pkgName, "")
}

// expandTemplate resolves $N references in template against pattern's capture groups for subject,
// returning fallback when there is nothing to resolve them from.
func expandTemplate(pattern, template, subject, fallback string) string {
	if pattern == "" || subject == "" {
		return fallback
	}
	// the anchored form is the one the pattern was matched on, so its groups are the author's
	re, err := regexp.Compile(anchorPattern(pattern))
	if err != nil {
		return fallback
	}
	m := re.FindStringSubmatchIndex(subject)
	if m == nil {
		return fallback
	}
	return string(re.ExpandString(nil, template, subject, m))
}

// compiledSearchRule is the compiled form of a SearchRule row: each pattern as an anchored regex.
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
		}{
			{row.MatchDistroVersion, &rule.distroVersion},
			{row.MatchPackageName, &rule.pkgName},
			{row.ExcludePackageName, &rule.excludePkgName},
			{row.MatchPackageVersion, &rule.pkgVersion},
			{row.ExcludePackageVersion, &rule.excludePkgVersion},
		} {
			if pc.pattern == "" {
				continue
			}
			*pc.dst = regexp.MustCompile(anchorPattern(pc.pattern)) // Validate compiled these already
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

// matches indicates whether the rule applies to the given package. Every set predicate must match,
// and a predicate whose subject the package does not carry fails the rule — matching occurs on what
// the package states, nothing is assumed about what it left unsaid. Exclude* predicates are the one
// exception in spirit: they only reject when their subject is present and matches (an absent subject
// cannot prove the exclusion).
func (r *compiledSearchRule) matches(p pkg.Package) bool {
	if r.hasDistroPredicate() && !r.matchesDistro(p.Distro) {
		return false
	}
	if r.row.MatchEcosystem != "" && !strings.EqualFold(r.row.MatchEcosystem, string(p.Type)) {
		return false
	}

	if r.pkgName != nil && (p.Name == "" || !r.pkgName.MatchString(p.Name)) {
		return false
	}
	if r.excludePkgName != nil && p.Name != "" && r.excludePkgName.MatchString(p.Name) {
		return false
	}
	if r.pkgVersion != nil && (p.Version == "" || !r.pkgVersion.MatchString(p.Version)) {
		return false
	}
	if r.excludePkgVersion != nil && p.Version != "" && r.excludePkgVersion.MatchString(p.Version) {
		return false
	}
	// guard against a hand-crafted rule with no predicate at all, which is rejected at creation
	// time (see Validate) and would otherwise speak for every package
	return r.pkgName != nil || r.pkgVersion != nil || r.row.MatchDistroName != "" || r.row.MatchEcosystem != ""
}

// matchesDistro indicates whether the rule's distro predicates match the package's OS. A package
// with no distro (a language ecosystem package) names no OS, so no distro predicate can match it.
func (r *compiledSearchRule) matchesDistro(d *distro.Distro) bool {
	if d == nil {
		return false
	}
	if r.row.MatchDistroName != "" && !strings.EqualFold(r.row.MatchDistroName, d.Name()) {
		return false
	}
	if r.distroVersion != nil && !r.matchesDistroVersion(d) {
		return false
	}
	return true
}

// matchesDistroVersion mirrors what a distro version pattern means for an OS specifier (see
// OSSpecifier.matchesVersionPattern): match the release version, or failing that the version label.
func (r *compiledSearchRule) matchesDistroVersion(d *distro.Distro) bool {
	if d.Version != "" && r.distroVersion.MatchString(d.Version) {
		return true
	}
	return d.LabelVersion() != "" && r.distroVersion.MatchString(d.LabelVersion())
}

func matchingRules(idx *searchRuleIndex, p pkg.Package) []*compiledSearchRule {
	var buf [16]*compiledSearchRule
	var matched []*compiledSearchRule
	for _, r := range idx.candidates(p, buf[:0]) {
		if r.matches(p) {
			matched = append(matched, r)
		}
	}
	return matched
}

// highestPriority narrows matched rules to those at the highest priority among them: precedence is
// stated by rank, and rules tied at that priority all apply together.
//
// Rules that substitute nothing are outside that contest and always apply (see
// SearchRule.hasSubstitution). Priority decides which substitution describes a package -- which
// channel, OS name, or extra names its lookup uses -- and such a rule substitutes nothing, so it has
// nothing to win or lose against one. Ranking it anyway would mean a package matching a stream rule
// silently lost the statement that its vendor's data is the whole picture, which would have to be
// restated on every stream rule to survive.
func highestPriority(matched []*compiledSearchRule) []*compiledSearchRule {
	if len(matched) < 2 {
		return matched
	}
	best, ranked := 0, false
	for _, r := range matched {
		if !r.row.hasSubstitution() {
			continue
		}
		if !ranked || r.row.Priority > best {
			best, ranked = r.row.Priority, true
		}
	}
	out := make([]*compiledSearchRule, 0, len(matched))
	for _, r := range matched {
		if !r.row.hasSubstitution() || r.row.Priority == best {
			out = append(out, r)
		}
	}
	return out
}
