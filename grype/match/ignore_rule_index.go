package match

// ignoreRuleIndex is an IgnoreFilter over an ordered list of IgnoreRules. For any match it returns the same
// rules, in the same order, as calling IgnoreMatch on every rule in the list, but it only evaluates the rules
// that could apply to that match.
//
// A rule that names a vulnerability can only apply to a match carrying that ID (see eachMatchVulnerabilityID),
// so those rules are grouped by vulnerability ID and only evaluated against matches with that ID: the match's
// own ID, or for IncludeAliases rules also one of its related vulnerability IDs. Rules without a vulnerability
// are evaluated against every match.
//
// Each rule's conditions are built once, when the index is built, rather than once per match, and rules that
// can never apply (VEX rules and rules without criteria) are left out.
//
// TODO: ignoreRulesByIndex in grype/vulnerability_matcher.go is a second group-by index over ignore filters,
// used for the filters that matchers return. The two should eventually be one implementation. Note that they
// differ today: this index returns every applicable rule in the original order, while ignoreRulesByIndex
// returns only the first hit, and it groups rules by literal package name and location, which is not safe
// for regex names, and for glob locations it only guards against `*` (not `?`, `[...]` or `{a,b}`).
type ignoreRuleIndex struct {
	// byVulnerabilityID holds rules that apply only to a match with exactly this vulnerability ID
	byVulnerabilityID map[string][]indexedIgnoreRule
	// byAliasID holds IncludeAliases rules, which apply to a match with this ID as its own or a related ID
	byAliasID map[string][]indexedIgnoreRule
	ungrouped []indexedIgnoreRule
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
		byAliasID:         make(map[string][]indexedIgnoreRule),
	}
	for i, rule := range rules {
		conditions := rule.matchConditions()
		if len(conditions) == 0 {
			continue
		}
		r := indexedIgnoreRule{position: i, rule: rule, conditions: conditions}
		switch {
		case rule.Vulnerability == "":
			index.ungrouped = append(index.ungrouped, r)
		case rule.IncludeAliases:
			index.byAliasID[rule.Vulnerability] = append(index.byAliasID[rule.Vulnerability], r)
		default:
			index.byVulnerabilityID[rule.Vulnerability] = append(index.byVulnerabilityID[rule.Vulnerability], r)
		}
	}
	return index
}

// IgnoreMatch returns every rule that applies to the match, in the order the rules were given.
func (i ignoreRuleIndex) IgnoreMatch(match Match) []IgnoreRule {
	// gather the candidate lists, each already in original order; the buffer covers the common case of a match
	// with a couple of related vulnerabilities without allocating
	var buf [6][]indexedIgnoreRule
	lists := buf[:0]
	for _, l := range [][]indexedIgnoreRule{i.ungrouped, i.byVulnerabilityID[match.Vulnerability.ID]} {
		if len(l) > 0 {
			lists = append(lists, l)
		}
	}
	if len(i.byAliasID) > 0 {
		eachMatchVulnerabilityID(&match, true, func(id string) bool {
			if l := i.byAliasID[id]; len(l) > 0 {
				lists = append(lists, l)
			}
			return true
		})
	}

	var applied []IgnoreRule
	last := -1
	for {
		// take the lowest position across the lists, so the applied rules keep their original order
		best := -1
		for j, l := range lists {
			if len(l) > 0 && (best < 0 || l[0].position < lists[best][0].position) {
				best = j
			}
		}
		if best < 0 {
			return applied
		}
		next := &lists[best][0]
		lists[best] = lists[best][1:]
		// an alias rule is reached once per matching ID, and since positions are taken in order the repeats are
		// adjacent
		if next.position == last {
			continue
		}
		last = next.position
		if conditionsApply(match, next.conditions) {
			applied = append(applied, next.rule)
		}
	}
}
