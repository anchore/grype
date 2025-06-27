package result

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ Provider = (*provider)(nil)

type Provider interface {
	FindResults(criteria ...vulnerability.Criteria) (Set, error)
}

type provider struct {
	vulnProvider vulnerability.Provider
	catalogedPkg pkg.Package // this is what is passed into the matcher
	matcher      match.MatcherType
}

func NewProvider(vp vulnerability.Provider, catalogedPkg pkg.Package, matcher match.MatcherType) Provider {
	return provider{
		vulnProvider: vp,
		catalogedPkg: catalogedPkg,
		matcher:      matcher,
	}
}

func (p provider) FindResults(criteria ...vulnerability.Criteria) (Set, error) {
	results := Set{}
	// get each iteration here so detailProvider will have the specific values used for searches
	for _, cs := range search.CriteriaIterator(criteria) {
		vulns, err := p.vulnProvider.FindVulnerabilities(cs...)
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
				Details:         detailProvider(p.matcher, p.catalogedPkg, criteria, v),
				Package:         &p.catalogedPkg,
			}

			results[ID(v.ID)] = append(results[ID(v.ID)], newResult)
		}
	}
	return results, nil
}

func detailProvider(matcher match.MatcherType, catalogedPkg pkg.Package, criteriaSet []vulnerability.Criteria, vuln vulnerability.Vulnerability) match.Details {
	var cpeParams []match.CPEParameters
	var distroParams []match.DistroParameters
	var ecosystemParams []match.EcosystemParameters
	var pkgParams *match.PackageParameter

	for i := 0; i < len(criteriaSet); i++ {
		switch c := criteriaSet[i].(type) {
		case *search.PackageNameCriteria:
			if pkgParams == nil {
				pkgParams = &match.PackageParameter{}
			}
			pkgParams.Name = c.PackageName

		case *search.VersionCriteria:
			if pkgParams == nil {
				pkgParams = &match.PackageParameter{}
			}
			pkgParams.Version = c.Version.Raw

		case *search.EcosystemCriteria:
			ecosystemParams = append(ecosystemParams, match.EcosystemParameters{
				Language:  c.Language.String(),
				Namespace: vuln.Namespace, // TODO: this is a holdover and will be removed in the future
			})

		case *search.CPECriteria:

			cpeParams = append(cpeParams, match.CPEParameters{
				Namespace: vuln.Namespace, // TODO: this is a holdover and will be removed in the future
				CPEs: []string{
					c.CPE.Attributes.BindToFmtString(),
				},
			})

		case *search.DistroCriteria:
			for _, d := range c.Distros {
				distroParams = append(distroParams, match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    d.Type.String(),
						Version: d.VersionString(),
					},
					Namespace: vuln.Namespace, // TODO: this is a holdover and will be removed in the future
				})
			}
		}
	}

	// apply any discovered package parameters to the ecosystem, cpe, and distro parameters
	distroMatchType := match.ExactDirectMatch
	if pkgParams != nil {
		if catalogedPkg.Name != pkgParams.Name {
			// if the cataloged package name does not match the package parameter, then this is an indirect match
			distroMatchType = match.ExactIndirectMatch
		}
		for i := range ecosystemParams {
			ecosystemParams[i].Package = *pkgParams
		}
		for i := range cpeParams {
			cpeParams[i].Package = *pkgParams
		}
		for i := range distroParams {
			distroParams[i].Package = *pkgParams
		}
	}

	var constraintStr string
	if vuln.Constraint != nil {
		constraintStr = vuln.Constraint.String()
	}

	// create the details for the vulnerability
	var details match.Details
	for _, cpeParam := range cpeParams {
		details = append(details,
			match.Detail{
				Type:       match.CPEMatch,
				Matcher:    matcher,
				SearchedBy: cpeParam,
				Found: match.CPEResult{
					VulnerabilityID:   vuln.ID,
					VersionConstraint: constraintStr,
				},
				Confidence: 0.9, // TODO: this is hard coded for now
			},
		)
	}

	for _, distroParam := range distroParams {
		details = append(details,
			match.Detail{
				Type:       distroMatchType,
				Matcher:    matcher,
				SearchedBy: distroParam,
				Found: match.DistroResult{
					VulnerabilityID:   vuln.ID,
					VersionConstraint: constraintStr,
				},
				Confidence: 1.0, // TODO: this is hard coded for now
			},
		)
	}

	for _, ecosystemParam := range ecosystemParams {
		details = append(details,
			match.Detail{
				Type:       match.ExactDirectMatch,
				Matcher:    matcher,
				SearchedBy: ecosystemParam,
				Found: match.EcosystemResult{
					VulnerabilityID:   vuln.ID,
					VersionConstraint: constraintStr,
				},
			},
		)
	}

	return details
}
