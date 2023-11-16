package match

import (
	"github.com/bmatcuk/doublestar/v2"
)

// An IgnoredMatch is a vulnerability Match that has been ignored because one or more IgnoreRules applied to the match.
type IgnoredMatch struct {
	Match

	// AppliedIgnoreRules are the rules that were applied to the match that caused Grype to ignore it.
	AppliedIgnoreRules []IgnoreRule
}

// An IgnoreRule specifies criteria for a vulnerability match to meet in order
// to be ignored. Not all criteria (fields) need to be specified, but all
// specified criteria must be met by the vulnerability match in order for the
// rule to apply.
type IgnoreRule struct {
	Vulnerability    string            `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	Reason           string            `yaml:"reason" json:"reason" mapstructure:"reason"`
	Namespace        string            `yaml:"namespace" json:"namespace" mapstructure:"namespace"`
	FixState         string            `yaml:"fix-state" json:"fix-state" mapstructure:"fix-state"`
	Package          IgnoreRulePackage `yaml:"package" json:"package" mapstructure:"package"`
	VexStatus        string            `yaml:"vex-status" json:"vex-status" mapstructure:"vex-status"`
	VexJustification string            `yaml:"vex-justification" json:"vex-justification" mapstructure:"vex-justification"`
}

// IgnoreRulePackage describes the Package-specific fields that comprise the IgnoreRule.
type IgnoreRulePackage struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Version  string `yaml:"version" json:"version" mapstructure:"version"`
	Language string `yaml:"language" json:"language" mapstructure:"language"`
	Type     string `yaml:"type" json:"type" mapstructure:"type"`
	Location string `yaml:"location" json:"location" mapstructure:"location"`
}

// ApplyIgnoreRules iterates through the provided matches and, for each match,
// determines if the match should be ignored, by evaluating if any of the
// provided IgnoreRules apply to the match. If any rules apply to the match, all
// applicable rules are attached to the Match to form an IgnoredMatch.
// ApplyIgnoreRules returns two collections: the matches that are not being
// ignored, and the matches that are being ignored.
func ApplyIgnoreRules(matches Matches, rules []IgnoreRule) (Matches, []IgnoredMatch) {
	var ignoredMatches []IgnoredMatch
	remainingMatches := NewMatches()

	for _, match := range matches.Sorted() {
		var applicableRules []IgnoreRule

		for _, rule := range rules {
			if shouldIgnore(match, rule) {
				applicableRules = append(applicableRules, rule)
			}
		}

		if len(applicableRules) > 0 {
			ignoredMatches = append(ignoredMatches, IgnoredMatch{
				Match:              match,
				AppliedIgnoreRules: applicableRules,
			})

			continue
		}

		remainingMatches.Add(match)
	}

	return remainingMatches, ignoredMatches
}

func shouldIgnore(match Match, rule IgnoreRule) bool {
	// VEX rules are handled by the vex processor
	if rule.VexStatus != "" {
		return false
	}

	ignoreConditions := getIgnoreConditionsForRule(rule)
	if len(ignoreConditions) == 0 {
		// this rule specifies no criteria, so it doesn't apply to the Match
		return false
	}

	for _, condition := range ignoreConditions {
		if !condition(match) {
			// as soon as one rule criterion doesn't apply, we know this rule doesn't apply to the Match
			return false
		}
	}

	// all criteria specified in the rule apply to this Match
	return true
}

// HasConditions returns true if the ignore rule has conditions
// that can cause a match to be ignored
func (ir IgnoreRule) HasConditions() bool {
	return len(getIgnoreConditionsForRule(ir)) == 0
}

// An ignoreCondition is a function that returns a boolean indicating whether
// the given Match should be ignored.
type ignoreCondition func(match Match) bool

func getIgnoreConditionsForRule(rule IgnoreRule) []ignoreCondition {
	var ignoreConditions []ignoreCondition

	if v := rule.Vulnerability; v != "" {
		ignoreConditions = append(ignoreConditions, ifVulnerabilityApplies(v))
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

	return ignoreConditions
}

func ifFixStateApplies(fs string) ignoreCondition {
	return func(match Match) bool {
		return fs == string(match.Vulnerability.Fix.State)
	}
}

func ifVulnerabilityApplies(vulnerability string) ignoreCondition {
	return func(match Match) bool {
		return vulnerability == match.Vulnerability.ID
	}
}

func ifNamespaceApplies(namespace string) ignoreCondition {
	return func(match Match) bool {
		return namespace == match.Vulnerability.Namespace
	}
}

func ifPackageNameApplies(name string) ignoreCondition {
	return func(match Match) bool {
		return name == match.Package.Name
	}
}

func ifPackageVersionApplies(version string) ignoreCondition {
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
