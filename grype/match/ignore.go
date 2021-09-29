package match

import "github.com/bmatcuk/doublestar/v2"

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
	Vulnerability string            `yaml:"vulnerability" json:"vulnerability" mapstructure:"vulnerability"`
	Package       IgnoreRulePackage `yaml:"package" json:"package" mapstructure:"package"`
}

// IgnoreRulePackage describes the Package-specific fields that comprise the IgnoreRule.
type IgnoreRulePackage struct {
	Name     string `yaml:"name" json:"name" mapstructure:"name"`
	Version  string `yaml:"version" json:"version" mapstructure:"version"`
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
	if len(rules) == 0 {
		return matches, nil
	}

	var ignoredMatches []IgnoredMatch
	remainingMatches := NewMatches()

	for match := range matches.Enumerate() {
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

		remainingMatches.add(match.Package.ID, match)
	}

	return remainingMatches, ignoredMatches
}

func shouldIgnore(match Match, rule IgnoreRule) bool {
	ignoreConditions := getIgnoreConditionsForRule(rule)
	if len(ignoreConditions) == 0 {
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

// An ignoreCondition is a function that returns a boolean indicating whether
// the given Match should be ignored.
type ignoreCondition func(match Match) bool

func getIgnoreConditionsForRule(rule IgnoreRule) []ignoreCondition {
	var ignoreConditions []ignoreCondition

	if v := rule.Vulnerability; v != "" {
		ignoreConditions = append(ignoreConditions, ifVulnerabilityApplies(v))
	}

	if n := rule.Package.Name; n != "" {
		ignoreConditions = append(ignoreConditions, ifPackageNameApplies(n))
	}

	if v := rule.Package.Version; v != "" {
		ignoreConditions = append(ignoreConditions, ifPackageVersionApplies(v))
	}

	if t := rule.Package.Type; t != "" {
		ignoreConditions = append(ignoreConditions, ifPackageTypeApplies(t))
	}

	if l := rule.Package.Location; l != "" {
		ignoreConditions = append(ignoreConditions, ifPackageLocationApplies(l))
	}

	return ignoreConditions
}

func ifVulnerabilityApplies(vulnerability string) ignoreCondition {
	return func(match Match) bool {
		return vulnerability == match.Vulnerability.ID
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

func ifPackageTypeApplies(t string) ignoreCondition {
	return func(match Match) bool {
		return t == string(match.Package.Type)
	}
}

func ifPackageLocationApplies(location string) ignoreCondition {
	return func(match Match) bool {
		return locationAppliesToMatch(location, match)
	}
}

func locationAppliesToMatch(location string, match Match) bool {
	for _, packageLocation := range match.Package.Locations {
		doesLocationMatch, err := doublestar.Match(location, packageLocation.String())
		if err != nil {
			continue
		}

		if doesLocationMatch {
			return true
		}
	}

	return false
}
