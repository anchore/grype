package result

import (
	"cmp"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// Rank decides which result wins when results for one vulnerability disagree: the higher Priority
// wins, then the stronger match type. The package's own searches rank at priority 0 and a search
// rule's search at the rule's priority (see v6.SearchRule), so a rule's records outrank the
// package's own when its priority is positive, and rank below them when it is negative.
type Rank struct {
	Priority int

	// MatchType is the strongest match type of the details the result was found with; details merged
	// in later do not change it
	MatchType match.Type
}

// rankOf ranks a result by the criteria set that found it (see search.RuleCriteria).
func rankOf(cs []vulnerability.Criteria, details match.Details) Rank {
	r := Rank{MatchType: details.BestType()}
	for _, c := range cs {
		if rc, ok := c.(*search.RuleCriteria); ok {
			r.Priority = rc.Priority
		}
	}
	return r
}

// Compare is positive when r outranks o.
func (r Rank) Compare(o Rank) int {
	if c := cmp.Compare(r.Priority, o.Priority); c != 0 {
		return c
	}
	return -match.CompareTypes(r.MatchType, o.MatchType)
}
