package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

type Provider interface {
	FindResults(criteria ...vulnerability.Criteria) (ResultSet, error)
}

type detailProvider func([]vulnerability.Criteria, vulnerability.Vulnerability) match.Details

type provider struct {
	detailProvider
	vulnProvider vulnerability.Provider
}

func NewProvider(vp vulnerability.Provider, details detailProvider) Provider {
	return provider{
		vulnProvider:   vp,
		detailProvider: details,
	}
}

func (p provider) FindResults(criteria ...vulnerability.Criteria) (ResultSet, error) {
	results := ResultSet{}
	// get each iteration here so detailProvider will have the specific values used for searches
	for _, row := range search.CriteriaIterator(criteria) {
		vulns, err := p.vulnProvider.FindVulnerabilities(row...)
		if err != nil {
			return ResultSet{}, err
		}
		for _, v := range vulns {
			result, ok := results[ResultID(v.ID)]
			details := p.detailProvider(criteria, v)
			if ok {
				result.Vulnerabilities = append(result.Vulnerabilities, v)
				result.Details = append(result.Details, details...)
			} else {
				result = Result{
					ID:              ResultID(v.ID),
					Vulnerabilities: []vulnerability.Vulnerability{v},
					Details:         details,
				}
			}
			results[ResultID(v.ID)] = result
		}
	}
	return results, nil
}

var _ Provider = (*provider)(nil)
