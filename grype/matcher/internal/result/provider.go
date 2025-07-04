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
	cpeParams, distroParams, ecosystemParams, pkgParams := extractSearchParameters(criteriaSet, vuln)
	distroMatchType := determineMatchType(catalogedPkg, pkgParams)
	applyPackageParamsToSearchParams(pkgParams, &cpeParams, &distroParams, &ecosystemParams)
	constraintStr := getConstraintString(vuln)

	return buildMatchDetails(matcher, distroMatchType, constraintStr, vuln, cpeParams, distroParams, ecosystemParams)
}

// extractSearchParameters processes criteria set and extracts search parameters for different match types
func extractSearchParameters(criteriaSet []vulnerability.Criteria, vuln vulnerability.Vulnerability) ([]match.CPEParameters, []match.DistroParameters, []match.EcosystemParameters, *match.PackageParameter) {
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

	return cpeParams, distroParams, ecosystemParams, pkgParams
}

// determineMatchType determines if this is a direct or indirect match based on package names
func determineMatchType(catalogedPkg pkg.Package, pkgParams *match.PackageParameter) match.Type {
	if pkgParams != nil && catalogedPkg.Name != pkgParams.Name {
		// if the cataloged package name does not match the package parameter, then this is an indirect match
		return match.ExactIndirectMatch
	}
	return match.ExactDirectMatch
}

// applyPackageParamsToSearchParams applies discovered package parameters to search parameters
func applyPackageParamsToSearchParams(pkgParams *match.PackageParameter, cpeParams *[]match.CPEParameters, distroParams *[]match.DistroParameters, ecosystemParams *[]match.EcosystemParameters) {
	if pkgParams == nil {
		return
	}

	for i := range *ecosystemParams {
		(*ecosystemParams)[i].Package = *pkgParams
	}
	for i := range *cpeParams {
		(*cpeParams)[i].Package = *pkgParams
	}
	for i := range *distroParams {
		(*distroParams)[i].Package = *pkgParams
	}
}

// getConstraintString safely extracts constraint string from vulnerability
func getConstraintString(vuln vulnerability.Vulnerability) string {
	if vuln.Constraint != nil {
		return vuln.Constraint.String()
	}
	return ""
}

// buildMatchDetails creates the final match details from all parameters
func buildMatchDetails(matcher match.MatcherType, distroMatchType match.Type, constraintStr string, vuln vulnerability.Vulnerability, cpeParams []match.CPEParameters, distroParams []match.DistroParameters, ecosystemParams []match.EcosystemParameters) match.Details {
	var details match.Details

	// add CPE match details
	for _, cpeParam := range cpeParams {
		details = append(details, match.Detail{
			Type:       match.CPEMatch,
			Matcher:    matcher,
			SearchedBy: cpeParam,
			Found: match.CPEResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: constraintStr,
			},
			Confidence: 0.9, // TODO: this is hard coded for now
		})
	}

	// add distro match details
	for _, distroParam := range distroParams {
		details = append(details, match.Detail{
			Type:       distroMatchType,
			Matcher:    matcher,
			SearchedBy: distroParam,
			Found: match.DistroResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: constraintStr,
			},
			Confidence: 1.0, // TODO: this is hard coded for now
		})
	}

	// add ecosystem match details
	for _, ecosystemParam := range ecosystemParams {
		details = append(details, match.Detail{
			Type:       match.ExactDirectMatch,
			Matcher:    matcher,
			SearchedBy: ecosystemParam,
			Found: match.EcosystemResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: constraintStr,
			},
		})
	}

	return details
}
