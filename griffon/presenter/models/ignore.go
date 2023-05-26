package models

import "github.com/nextlinux/griffon/griffon/match"

type IgnoredMatch struct {
	Match
	AppliedIgnoreRules []IgnoreRule `json:"appliedIgnoreRules"`
}

type IgnoreRule struct {
	Vulnerability string             `json:"vulnerability,omitempty"`
	FixState      string             `json:"fix-state,omitempty"`
	Package       *IgnoreRulePackage `json:"package,omitempty"`
}

type IgnoreRulePackage struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Type     string `json:"type,omitempty"`
	Location string `json:"location,omitempty"`
}

func newIgnoreRule(r match.IgnoreRule) IgnoreRule {
	var ignoreRulePackage *IgnoreRulePackage

	// We'll only set the package part of the rule not to `nil` if there are any values to fill out.
	if p := r.Package; p.Name != "" || p.Version != "" || p.Type != "" || p.Location != "" {
		ignoreRulePackage = &IgnoreRulePackage{
			Name:     r.Package.Name,
			Version:  r.Package.Version,
			Type:     r.Package.Type,
			Location: r.Package.Location,
		}
	}

	return IgnoreRule{
		Vulnerability: r.Vulnerability,
		FixState:      r.FixState,
		Package:       ignoreRulePackage,
	}
}

func mapIgnoreRules(rules []match.IgnoreRule) []IgnoreRule {
	var result []IgnoreRule

	for _, rule := range rules {
		result = append(result, newIgnoreRule(rule))
	}

	return result
}
