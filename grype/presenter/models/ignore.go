package models

import "github.com/anchore/grype/grype/match"

type IgnoredMatch struct {
	Match
	AppliedIgnoreRules []IgnoreRule `json:"appliedIgnoreRules"`
}

type IgnoreRule struct {
	Vulnerability    string             `json:"vulnerability,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	FixState         string             `json:"fix-state,omitempty"`
	Package          *IgnoreRulePackage `json:"package,omitempty"`
	VexStatus        string             `json:"vex-status,omitempty"`
	VexJustification string             `json:"vex-justification,omitempty"`
	MatchType        string             `json:"match-type,omitempty"`
}

type IgnoreRulePackage struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Type         string `json:"type,omitempty"`
	Location     string `json:"location,omitempty"`
	UpstreamName string `json:"upstream-name,omitempty"`
}

func newIgnoreRule(r match.IgnoreRule) IgnoreRule {
	var ignoreRulePackage *IgnoreRulePackage

	// We'll only set the package part of the rule not to `nil` if there are any values to fill out.
	if p := r.Package; p.Name != "" || p.Version != "" || p.Type != "" || p.Location != "" {
		ignoreRulePackage = &IgnoreRulePackage{
			Name:         r.Package.Name,
			Version:      r.Package.Version,
			Type:         r.Package.Type,
			Location:     r.Package.Location,
			UpstreamName: r.Package.UpstreamName,
		}
	}

	return IgnoreRule{
		Vulnerability:    r.Vulnerability,
		Reason:           r.Reason,
		FixState:         r.FixState,
		Package:          ignoreRulePackage,
		VexStatus:        r.VexStatus,
		VexJustification: r.VexJustification,
		MatchType:        string(r.MatchType),
	}
}

func mapIgnoreRules(rules []match.IgnoreRule) []IgnoreRule {
	var result []IgnoreRule

	for _, rule := range rules {
		result = append(result, newIgnoreRule(rule))
	}

	return result
}
