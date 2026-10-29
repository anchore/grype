package match

// ignoreRuleIndex is an IgnoreFilter over an ordered list of IgnoreRules. For any match it returns the same
// rules, in the same order, as calling IgnoreMatch on every rule in the list, but it only evaluates the rules
// that could apply to that match.
//
// A rule that names a vulnerability without IncludeAliases can only apply to a match with exactly that
// vulnerability ID, so those rules are grouped by vulnerability ID and only evaluated against matches with
// that ID. Every other rule (no vulnerability, or IncludeAliases set) is evaluated against every match.
//
// Each rule's conditions are built once, when the index is built, rather than once per match, and rules that
// can never apply (VEX rules and rules without criteria) are left out.
//
// TODO: ignoreRulesByIndex in grype/vulnerability_matcher.go is a second group-by index over ignore filters,
// used for the filters that matchers return. The two should eventually be one implementation. Note that they
// differ today: this index returns every applicable rule in the original order, while ignoreRulesByIndex
// returns only the first hit, and it groups rules by literal package name and location, which is not safe
// for regex names or glob locations.
type ignoreRuleIndex struct {
	byVulnerabilityID map[string][]indexedIgnoreRule
	ungrouped         []indexedIgnoreRule
}

type indexedIgnoreRule struct {
	// position is the rule's index in the original list, used to keep applied rules in their original order
	position   int
	rule       IgnoreRule
	conditions []ignoreCondition
}

var _ IgnoreFilter = (*ignoreRuleIndex)(nil)

func newIgnoreRuleIndex(rules []IgnoreRule) ignoreRuleIndex {
	index := ignoreRuleIndex{
		byVulnerabilityID: make(map[string][]indexedIgnoreRule),
	}
	for i, rule := range rules {
		conditions := rule.matchConditions()
		if len(conditions) == 0 {
			continue
		}
		r := indexedIgnoreRule{position: i, rule: rule, conditions: conditions}
		if rule.Vulnerability != "" && !rule.IncludeAliases {
			index.byVulnerabilityID[rule.Vulnerability] = append(index.byVulnerabilityID[rule.Vulnerability], r)
			continue
		}
		index.ungrouped = append(index.ungrouped, r)
	}
	return index
}

// IgnoreMatch returns every rule that applies to the match, in the order the rules were given.
func (i ignoreRuleIndex) IgnoreMatch(match Match) []IgnoreRule {
	byID := i.byVulnerabilityID[match.Vulnerability.ID]
	ungrouped := i.ungrouped

	var applied []IgnoreRule
	// both candidate lists are in original order, so merging them by position keeps that order
	for len(byID) > 0 || len(ungrouped) > 0 {
		var next *indexedIgnoreRule
		if len(ungrouped) == 0 || (len(byID) > 0 && byID[0].position < ungrouped[0].position) {
			next, byID = &byID[0], byID[1:]
		} else {
			next, ungrouped = &ungrouped[0], ungrouped[1:]
		}
		if conditionsApply(match, next.conditions) {
			applied = append(applied, next.rule)
		}
	}
	return applied
}
