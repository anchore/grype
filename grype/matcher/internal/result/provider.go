package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ Provider = (*provider)(nil)

type Provider interface {
	FindResults(criteria ...vulnerability.Criteria) (Set, error)
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

func (p provider) FindResults(criteria ...vulnerability.Criteria) (Set, error) {
	results := Set{}
	// get each iteration here so detailProvider will have the specific values used for searches
	for _, c := range search.CriteriaIterator(criteria) {
		vulns, err := p.vulnProvider.FindVulnerabilities(c...)
		if err != nil {
			return Set{}, err
		}
		for _, v := range vulns {
			if v.ID == "" {
				continue // skip vulnerabilities without an ID (should never happen)
			}

			newResult := Result{
				ID:              ID(v.ID),
				Vulnerabilities: []vulnerability.Vulnerability{v},
				Details:         p.detailProvider(criteria, v),
			}

			results[ID(v.ID)] = append(results[ID(v.ID)], newResult)
		}
	}
	return results, nil
}
