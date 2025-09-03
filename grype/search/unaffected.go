package search

import (
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*UnaffectedCriteria)(nil)

// ForUnaffected returns criteria which will cause the search to be against unaffected packages / vulnerabilities.
func ForUnaffected(unaffectedValue bool) vulnerability.Criteria {
	return &UnaffectedCriteria{
		UnaffectedValue: unaffectedValue,
	}
}

type UnaffectedCriteria struct {
	UnaffectedValue bool
}

func (c *UnaffectedCriteria) MatchesVulnerability(v vulnerability.Vulnerability) (bool, string, error) {
	// unaffected criteria filtering happens at the store level, so all vulnerabilities returned
	// from unaffected stores _should_ already match this criteria. Boolean indicator is a backup
	// sanity check.
	return v.Unaffected == c.UnaffectedValue, "", nil
}
