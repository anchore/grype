package search

import (
	"fmt"

	"github.com/anchore/grype/grype/vulnerability"
)

// ByID returns criteria to search by vulnerability ID, such as CVE-2024-9143
func ByID(id string) vulnerability.Criteria {
	return &IDCriteria{
		ID: id,
	}
}

// IDCriteria is able to match vulnerabilities to the assigned ID, such as CVE-2024-1000 or GHSA-g2x7-ar59-85z5
type IDCriteria struct {
	ID string
}

func (v *IDCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, string, error) {
	matchesID := vuln.ID == v.ID
	if !matchesID {
		return false, fmt.Sprintf("vulnerability ID %q does not match expected ID %q", vuln.ID, v.ID), nil
	}
	return true, "", nil
}

var _ interface {
	vulnerability.Criteria
} = (*IDCriteria)(nil)
