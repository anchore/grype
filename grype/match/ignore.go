package match

import (
	"regexp"
	"slices"

	"github.com/bmatcuk/doublestar/v2"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/artifact"
)

// IgnoreFilter implementations are used to filter matches, returning all applicable IgnoreRule(s) that applied,
// these could include an IgnoreRule with only a Reason value filled in for synthetically generated rules
type IgnoreFilter interface {
	IgnoreMatch(match Match) []IgnoreRule
}

// IgnoreSource identifies the class of rule that caused a match to end up in
// the ignored set. Consumers such as the --show-suppressed presenter can group
// or filter by this without pattern-matching on rule reason strings.
type IgnoreSource string

const (
	// IgnoreSourceUserRule marks matches suppressed by a user-provided ignore
	// rule (e.g. .grype.yaml, --ignore).
	IgnoreSourceUserRule IgnoreSource = "user-rule"

	// IgnoreSourceDistroFixed marks matches suppressed because the containing
	// distro package has a FIXED entry that covers this CVE. Emitted by
	// OwnershipIgnores called with reason "DistroPackageFixed" (introduced in
	// #3282 to suppress GHSAs on language packages inside fixed APKs).
	IgnoreSourceDistroFixed IgnoreSource = "distro-fixed"

	// IgnoreSourceExplicitExclusion marks matches dropped by the grype
	// database's explicit exclusion table (see ApplyExplicitIgnoreRules).
	IgnoreSourceExplicitExclusion IgnoreSource = "explicit-exclusion"

	// IgnoreSourceVEX marks matches suppressed by a VEX statement.
	IgnoreSourceVEX IgnoreSource = "vex"

	// IgnoreSourceHardcodedCorrection marks matches suppressed by any other
	// matcher-returned hard-coded ignore rule (e.g. per-package corrections
	// for known false positives).
	IgnoreSourceHardcodedCorrection IgnoreSource = "hardcoded-correction"
)

// ValidIgnoreSources returns every defined IgnoreSource value as a string
// slice. CLI flag validation and help text use this to enumerate the valid
// values without hard-coding the list twice.
func ValidIgnoreSources() []string {
	return []string{
		string(IgnoreSourceUserRule),
		string(IgnoreSourceDistroFixed),
		string(IgnoreSourceExplicitExclusion),
		string(IgnoreSourceVEX),
		string(IgnoreSourceHardcodedCorrection),
	}
}

// IsValidIgnoreSource reports whether s matches one of the defined
// IgnoreSource string values.
func IsValidIgnoreSource(s string) bool {
	switch IgnoreSource(s) {
	case IgnoreSourceUserRule,
		IgnoreSourceDistroFixed,
		IgnoreSourceExplicitExclusion,
		IgnoreSourceVEX,
		IgnoreSourceHardcodedCorrection:
		return true
	}
	return false
}

// An IgnoredMatch is a vulnerability Match that has been ignored because one or more IgnoreRules applied to the match.
type IgnoredMatch struct {
	Match

	// AppliedIgnoreRules are the rules that were applied to the match that caused Grype to ignore it.
	AppliedIgnoreRules []IgnoreRule

	// Sources identifies the category(ies) of rule that caused this match to
	// be suppressed. When more than one category applied to the same match
	// fingerprint (e.g. a user rule and a distro-fixed rule both matched, or
	// two independently-produced matches with the same fingerprint were
	// dropped for different reasons and later merged by fingerprint), all
	// applicable categories are preserved in first-observed order. Empty when
	// callers construct IgnoredMatch directly without tagging.
	Sources []IgnoreSource `json:"sources,omitempty"`
}

// WithSource appends src to the Sources slice if it is not already present,
// preserving order of first occurrence. Returns the receiver so calls can be
// chained.
func (im IgnoredMatch) WithSource(src IgnoreSource) IgnoredMatch {
	for _, existing := range im.Sources {
		if existing == src {
			return im
		}
	}
	im.Sources = append(im.Sources, src)
	return im
}

// TagIgnoredMatches returns a new slice where every entry has been tagged with
// the given IgnoreSource. Used by callers that produce a homogeneous batch of
// suppressions (e.g. all VEX suppressions, all user-rule suppressions).
func TagIgnoredMatches(matches []IgnoredMatch, src IgnoreSource) []IgnoredMatch {
	if len(matches) == 0 {
		return matches
	}
	out := make([]IgnoredMatch, len(matches))
	for i := range matches {
		out[i] = matches[i].WithSource(src)
	}
	return out
}

// DedupeIgnoredMatches collapses entries that share a Match.Fingerprint,
// merging Sources as a set (deduped, order-of-first-occurrence) and
// AppliedIgnoreRules as an append-only union (no dedupe, order-of-first-
// occurrence). Order of the returned slice follows first-observation order
// of each unique fingerprint.
func DedupeIgnoredMatches(matches []IgnoredMatch) []IgnoredMatch {
	if len(matches) < 2 {
		return matches
	}
	seen := make(map[Fingerprint]int, len(matches))
	out := make([]IgnoredMatch, 0, len(matches))
	for _, im := range matches {
		fp := im.Match.Fingerprint()
		if idx, ok := seen[fp]; ok {
			existing := out[idx]
			for _, s := range im.Sources {
				existing = existing.WithSource(s)
			}
			existing.AppliedIgnoreRules = append(existing.AppliedIgnoreRules, im.AppliedIgnoreRules...)
			out[idx] = existing
			continue
		}
		seen[fp] = len(out)
		out = append(out, im)
	}
	return out
}

// An IgnoreRule specifies criteria for a vulnerability match to meet in order
// to be ignored. Not all criteria (fields) need to be specified, but all
// specified criteria must be met by the vulnerability match in order for the
// rule to apply.
type IgnoreRule struct {
	Vulnerability    string            `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	IncludeAliases   bool              `yaml:"include-aliases" json:"include-aliases" mapstructure:"include-aliases"`
	Reason           string            `yaml:"reason" json:"reason" mapstructure:"reason"`
	Namespace        string            `yaml:"namespace" json:"namespace" mapstructure:"namespace"`
	FixState         string            `yaml:"fix-state" json:"fix-state" mapstructure:"fix-state"`
	Package          IgnoreRulePackage `yaml:"package" json:"package" mapstructure:"package"`
	VexStatus        string            `yaml:"vex-status" json:"vex-status" mapstructure:"vex-status"`
	VexJustification string            `yaml:"vex-justification" json:"vex-justification" mapstructure:"vex-justification"`
	MatchType        Type              `yaml:"match-type" json:"match-type" mapstructure:"match-type"`
}

// IgnoreRulePackage describes the Package-specific fields that comprise the IgnoreRule.
type IgnoreRulePackage struct {
	Name         string `yaml:"name" json:"name" mapstructure:"name"`
	Version      string `yaml:"version" json:"version" mapstructure:"version"`
	Language     string `yaml:"language" json:"language" mapstructure:"language"`
	Type         string `yaml:"type" json:"type" mapstructure:"type"`
	Location     string `yaml:"location" json:"location" mapstructure:"location"`
	UpstreamName string `yaml:"upstream-name" json:"upstream-name" mapstructure:"upstream-name"`
}

// IgnoreRelatedPackage is an IgnoreFilter that looks at package relationships to drop vulnerabilities on specific packages
// that meet the specified relationship rules
type IgnoreRelatedPackage struct {
	Reason           string
	RelationshipType artifact.RelationshipType `yaml:"relationship-type" json:"relationship-type" mapstructure:"relationship-type"`
	VulnerabilityID  string                    `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	RelatedPackageID pkg.ID                    `yaml:"related-package" json:"related-package" mapstructure:"related-package"`
}

func (i IgnoreRelatedPackage) IgnoreMatch(m Match) []IgnoreRule {
	if m.Vulnerability.ID != i.VulnerabilityID {
		matches := false
		for _, related := range m.Vulnerability.RelatedVulnerabilities {
			if related.ID == i.VulnerabilityID {
				matches = true
				break
			}
		}
		if !matches {
			return nil
		}
	}
	relatedPackages := m.Package.RelatedPackages[i.RelationshipType]
	if relatedPackages == nil {
		return nil
	}
	// any findings for packages with files that this package owns by should be filtered out
	overlaps := false
	for _, ownerPkg := range relatedPackages {
		if ownerPkg.ID == i.RelatedPackageID {
			overlaps = true
			break
		}
	}
	if !overlaps {
		return nil
	}
	return []IgnoreRule{
		{
			// details about why the vulnerability is being ignored
			Vulnerability:  i.VulnerabilityID,
			IncludeAliases: true,
			Reason:         i.Reason,
		},
	}
}

// ApplyIgnoreRules iterates through the provided matches and, for each match,
// determines if the match should be ignored, by evaluating if any of the
// provided IgnoreRules apply to the match. If any rules apply to the match, all
// applicable rules are attached to the Match to form an IgnoredMatch.
// ApplyIgnoreRules returns two collections: the matches that are not being
// ignored, and the matches that are being ignored.
func ApplyIgnoreRules(matches Matches, rules []IgnoreRule) (Matches, []IgnoredMatch) {
	matched, ignored := ApplyIgnoreFilters(matches.Sorted(), rules...)
	return NewMatches(matched...), ignored
}

// ApplyIgnoreFilters applies all the IgnoreFilter(s) to the provided set of matches,
// splitting the results into a set of matched matches and ignored matches
func ApplyIgnoreFilters[T IgnoreFilter](matches []Match, filters ...T) ([]Match, []IgnoredMatch) {
	var out []Match
	var ignoredMatches []IgnoredMatch

	for _, match := range matches {
		var applicableRules []IgnoreRule

		for _, filter := range filters {
			applicableRules = append(applicableRules, filter.IgnoreMatch(match)...)
		}

		if len(applicableRules) > 0 {
			ignoredMatches = append(ignoredMatches, IgnoredMatch{
				Match:              match,
				AppliedIgnoreRules: applicableRules,
			})

			continue
		}

		out = append(out, match)
	}

	return out, ignoredMatches
}

func (r IgnoreRule) IgnoreMatch(match Match) []IgnoreRule {
	// VEX rules are handled by the vex processor
	if r.VexStatus != "" {
		return nil
	}

	ignoreConditions := getIgnoreConditionsForRule(r)
	if len(ignoreConditions) == 0 {
		// this rule specifies no criteria, so it doesn't apply to the Match
		return nil
	}

	for _, condition := range ignoreConditions {
		if !condition(match) {
			// as soon as one rule criterion doesn't apply, we know this rule doesn't apply to the Match
			return nil
		}
	}

	// all criteria specified in the rule apply to this Match
	return []IgnoreRule{r}
}

// HasConditions returns true if the ignore rule has conditions
// that can cause a match to be ignored
func (r IgnoreRule) HasConditions() bool {
	return len(getIgnoreConditionsForRule(r)) == 0
}

// ignoreFilters implements match.IgnoreFilter on a slice of objects that implement the same interface
type ignoreFilters[T IgnoreFilter] []T

func (r ignoreFilters[T]) IgnoreMatch(match Match) []IgnoreRule {
	for _, rule := range r {
		ignores := rule.IgnoreMatch(match)
		if len(ignores) > 0 {
			return ignores
		}
	}
	return nil
}

var _ IgnoreFilter = (*ignoreFilters[IgnoreRule])(nil)

// An ignoreCondition is a function that returns a boolean indicating whether
// the given Match should be ignored.
type ignoreCondition func(match Match) bool

func getIgnoreConditionsForRule(rule IgnoreRule) []ignoreCondition {
	var ignoreConditions []ignoreCondition

	if v := rule.Vulnerability; v != "" {
		ignoreConditions = append(ignoreConditions, ifVulnerabilityApplies(v, rule.IncludeAliases))
	}

	if ns := rule.Namespace; ns != "" {
		ignoreConditions = append(ignoreConditions, ifNamespaceApplies(ns))
	}

	if n := rule.Package.Name; n != "" {
		ignoreConditions = append(ignoreConditions, ifPackageNameApplies(n))
	}

	if v := rule.Package.Version; v != "" {
		ignoreConditions = append(ignoreConditions, ifPackageVersionApplies(v))
	}

	if l := rule.Package.Language; l != "" {
		ignoreConditions = append(ignoreConditions, ifPackageLanguageApplies(l))
	}

	if t := rule.Package.Type; t != "" {
		ignoreConditions = append(ignoreConditions, ifPackageTypeApplies(t))
	}

	if l := rule.Package.Location; l != "" {
		ignoreConditions = append(ignoreConditions, ifPackageLocationApplies(l))
	}

	if fs := rule.FixState; fs != "" {
		ignoreConditions = append(ignoreConditions, ifFixStateApplies(fs))
	}

	if upstreamName := rule.Package.UpstreamName; upstreamName != "" {
		ignoreConditions = append(ignoreConditions, ifUpstreamPackageNameApplies(upstreamName))
	}

	if matchType := rule.MatchType; matchType != "" {
		ignoreConditions = append(ignoreConditions, ifMatchTypeApplies(matchType))
	}
	return ignoreConditions
}

func ifFixStateApplies(fs string) ignoreCondition {
	return func(match Match) bool {
		if fs == string(vulnerability.FixStateUnknown) &&
			match.Vulnerability.Fix.State == "" { // no fix state specified is effectively "unknown"
			return true
		}
		return fs == string(match.Vulnerability.Fix.State)
	}
}

func ifVulnerabilityApplies(vulnerability string, includeAliases bool) ignoreCondition {
	return func(match Match) bool {
		if vulnerability == match.Vulnerability.ID {
			return true
		}
		if includeAliases {
			for _, related := range match.Vulnerability.RelatedVulnerabilities {
				if vulnerability == related.ID {
					return true
				}
			}
		}
		return false
	}
}

func ifNamespaceApplies(namespace string) ignoreCondition {
	return func(match Match) bool {
		return namespace == match.Vulnerability.Namespace
	}
}

func packageNameRegex(packageName string) (*regexp.Regexp, error) {
	pattern := packageName
	if packageName[0] != '$' || packageName[len(packageName)-1] != '^' {
		pattern = "^" + packageName + "$"
	}
	return regexp.Compile(pattern)
}

func ifPackageNameApplies(name string) ignoreCondition {
	// with enough ignore rules, we could end up needlessly creating a lot of regexes, which is not ideal.
	// instead lets detect if the input string is a regex or not, and if it is, then compile it...
	// otherwise, we can just do a simple string comparison
	if isLikelyARegex(name) {
		pattern, err := packageNameRegex(name)
		if err != nil || pattern == nil {
			return func(Match) bool { return false }
		}

		return func(match Match) bool {
			return pattern.MatchString(match.Package.Name)
		}
	}
	return func(match Match) bool {
		return name == match.Package.Name
	}
}

func ifPackageVersionApplies(version string) ignoreCondition {
	// TODO I think we will might need to add the metadata compare logic here
	return func(match Match) bool {
		return version == match.Package.Version
	}
}

func ifPackageLanguageApplies(language string) ignoreCondition {
	return func(match Match) bool {
		return language == string(match.Package.Language)
	}
}

func ifPackageTypeApplies(t string) ignoreCondition {
	return func(match Match) bool {
		return t == string(match.Package.Type)
	}
}

func ifPackageLocationApplies(location string) ignoreCondition {
	return func(match Match) bool {
		return ruleLocationAppliesToMatch(location, match)
	}
}

func ifUpstreamPackageNameApplies(name string) ignoreCondition {
	// with enough ignore rules, we could end up needlessly creating a lot of regexes, which is not ideal.
	// instead lets detect if the input string is a regex or not, and if it is, then compile it...
	// otherwise, we can just do a simple string comparison
	if isLikelyARegex(name) {
		pattern, err := packageNameRegex(name)
		if err != nil {
			log.WithFields("name", name, "error", err).Debug("unable to parse name expression")
			return func(Match) bool { return false }
		}
		return func(match Match) bool {
			for _, upstream := range match.Package.Upstreams {
				if pattern.MatchString(upstream.Name) {
					return true
				}
			}
			return false
		}
	}
	return func(match Match) bool {
		for _, upstream := range match.Package.Upstreams {
			if name == upstream.Name {
				return true
			}
		}
		return false
	}
}

// isRegexPattern is a compiled regex that matches common regex characters. We intentionally leave out
// the '.' character, as it is a common character in package names and versions, and we do not want to
// treat it as a regex unless there is other evidence that it is a regex.
var isRegexPattern = regexp.MustCompile(`[\^\$\*\+\?\[\]\(\)\{\}\|\\]|\\[dDwWsSnrtfv]`)

func isLikelyARegex(s string) bool {
	return isRegexPattern.MatchString(s)
}

func ifMatchTypeApplies(matchType Type) ignoreCondition {
	return func(match Match) bool {
		return slices.Contains(match.Details.Types(), matchType)
	}
}

func ruleLocationAppliesToMatch(location string, match Match) bool {
	for _, packageLocation := range match.Package.Locations.ToSlice() {
		if ruleLocationAppliesToPath(location, packageLocation.RealPath) {
			return true
		}

		if ruleLocationAppliesToPath(location, packageLocation.AccessPath) {
			return true
		}
	}

	return false
}

func ruleLocationAppliesToPath(location, path string) bool {
	doesMatch, err := doublestar.Match(location, path)
	if err != nil {
		return false
	}

	return doesMatch
}
