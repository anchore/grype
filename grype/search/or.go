package search

import "github.com/anchore/grype/grype/vulnerability"

// orCriteria provides a way to specify multiple criteria to be used
type orCriteria struct {
	criteria []vulnerability.Criteria
}

func NewOrCriteria(criteria ...vulnerability.Criteria) vulnerability.Criteria {
	return &orCriteria{
		criteria: criteria,
	}
}

func (c *orCriteria) OptionalCriteria() []vulnerability.Criteria {
	return c.criteria
}

func (c *orCriteria) MatchesVulnerability(v vulnerability.Vulnerability) (bool, error) {
	for _, crit := range c.criteria {
		matches, err := crit.MatchesVulnerability(v)
		if matches || err != nil {
			return matches, err
		}
	}
	return false, nil
}

var _ interface {
	vulnerability.Criteria
	optionalCriteriaContainer
} = (*orCriteria)(nil)
