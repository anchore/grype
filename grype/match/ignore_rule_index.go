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
type ignoreRuleIndex struct {
	byVulnerabilityID map[string][]indexedIgnoreRule
	unindexed         []indexedIgnoreRule
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
		index.unindexed = append(index.unindexed, r)
	}
	return index
}

// IgnoreMatch returns every rule that applies to the match, in the order the rules were given.
func (i ignoreRuleIndex) IgnoreMatch(match Match) []IgnoreRule {
	byID := i.byVulnerabilityID[match.Vulnerability.ID]
	unindexed := i.unindexed

	var applied []IgnoreRule
	// both candidate lists are in original order, so merging them by position keeps that order
	for len(byID) > 0 || len(unindexed) > 0 {
		var next indexedIgnoreRule
		if len(unindexed) == 0 || (len(byID) > 0 && byID[0].position < unindexed[0].position) {
			next, byID = byID[0], byID[1:]
		} else {
			next, unindexed = unindexed[0], unindexed[1:]
		}
		applied = append(applied, next.rule.ignoreMatchWithConditions(match, next.conditions)...)
	}
	return applied
}
