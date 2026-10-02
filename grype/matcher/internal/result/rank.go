package result

import (
	"cmp"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// Rank decides which result wins when results for one vulnerability disagree: results found by a
// search rule's search (see v6.SearchRule) outrank the package's own, then the higher RulePriority
// wins, then the stronger match type. A rule's result outranks the package's own even when reached
// indirectly.
type Rank struct {
	FromSearchRule bool
	RulePriority   int

	// MatchType is the strongest match type of the details the result was found with; details merged
	// in later do not change it
	MatchType match.Type
}

// rankOf ranks a result by the criteria set that found it (see search.RuleCriteria).
func rankOf(cs []vulnerability.Criteria, details match.Details) Rank {
	r := Rank{MatchType: details.BestType()}
	for _, c := range cs {
		if rc, ok := c.(*search.RuleCriteria); ok {
			r.FromSearchRule, r.RulePriority = true, rc.Priority
		}
	}
	return r
}

// Compare is positive when r outranks o.
func (r Rank) Compare(o Rank) int {
	if r.FromSearchRule != o.FromSearchRule {
		if r.FromSearchRule {
			return 1
		}
		return -1
	}
	if c := cmp.Compare(r.RulePriority, o.RulePriority); c != 0 {
		return c
	}
	return -match.CompareTypes(r.MatchType, o.MatchType)
}
