package search

import (
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*UnaffectedCriteria)(nil)

// ForUnaffected returns criteria which will cause the search to be against unaffected packages / vulnerabilities.
func ForUnaffected() vulnerability.Criteria {
	return &UnaffectedCriteria{}
}

type UnaffectedCriteria struct{}

func (c *UnaffectedCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	// unaffected criteria filtering happens at the store level, so all vulnerabilities returned
	// from unaffected stores already match this criteria
	return true, "", nil
}
