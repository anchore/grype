package search

import "github.com/anchore/grype/grype/vulnerability"

// ByFunc returns criteria which will use the provided function to filter vulnerabilities
func ByFunc(criteriaFunc func(vulnerability.Vulnerability) (bool, error)) vulnerability.Criteria {
	return funcCriteria{fn: criteriaFunc}
}

// funcCriteria implements vulnerability.Criteria by providing a function implementing the same signature as MatchVulnerability
type funcCriteria struct {
	fn func(vulnerability.Vulnerability) (bool, error)
}

func (f funcCriteria) MatchesVulnerability(value vulnerability.Vulnerability) (bool, error) {
	return f.fn(value)
}

var _ vulnerability.Criteria = (*funcCriteria)(nil)
