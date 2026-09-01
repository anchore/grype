package result

import (
	"slices"
	"sort"

	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/cpeversion"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier/gosymbols"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

var _ Provider = (*provider)(nil)

type Provider interface {
	FindResults(criteria ...vulnerability.Criteria) (Set, error)

	// FindAll runs FindResults and includes all unaffected records
	FindAll(criteria ...vulnerability.Criteria) (Set, error)
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
		// the provider's search rules may route this search to additional OS rows (a release-stream
		// channel, another vendor's OS name); each is its own store search, so how confidently its
		// rows speak for this package is known here, per search, and travels on the details it
		// produces
		for _, s := range applySearchRules(p.vulnProvider, p.catalogedPkg, cs) {
			vulns, err := p.vulnProvider.FindVulnerabilities(s.criteria...)
			if err != nil {
				return Set{}, err
			}

			for _, v := range vulns {
				if v.ID == "" {
					continue // skip vulnerabilities without an ID (should never happen)
				}

				details := detailProvider(p.matcher, p.catalogedPkg, s.criteria, v)
				if s.confidence > 0 {
					details = append(details, match.ConfidenceDetail(p.matcher, s.stream, s.confidence))
				}

				newResult := Result{
					ID:              v.ID,
					Vulnerabilities: []vulnerability.Vulnerability{v},
					Details:         details,
					Package:         &p.catalogedPkg,
				}

				results[v.ID] = append(results[v.ID], newResult)
			}
		}
	}
	return results, nil
}

func (p provider) FindAll(criteria ...vulnerability.Criteria) (Set, error) {
	// the affected records and the unaffected ones live in separate stores and are reached by
	// mutually exclusive searches, so the only way to hold both at once is to ask twice and union
	affected, err := p.FindResults(criteria...)
	if err != nil {
		return Set{}, err
	}

	// note: no version criteria on either search. The split needs the records this version falls
	// outside of -- a record already fixed at this version is what distinguishes "resolved" from
	// "this stream is describing some other release line", and a nak that does not cover this
	// version must not read as a denial.
	unaffected, err := p.FindResults(append(slices.Clone(criteria), search.ForUnaffected())...)
	if err != nil {
		return Set{}, err
	}

	return affected.Merge(unaffected), nil
}

func detailProvider(matcher match.MatcherType, catalogedPkg pkg.Package, criteriaSet []vulnerability.Criteria, vuln vulnerability.Vulnerability) match.Details {
	cpeParams, distroParams, ecosystemParams, pkgParams := extractSearchParameters(criteriaSet, vuln, catalogedPkg)
	distroMatchType := determineMatchType(catalogedPkg, pkgParams)
	applyPackageParamsToSearchParams(pkgParams, &cpeParams, &distroParams, &ecosystemParams)
	constraintStr := getConstraintString(vuln)
	// the vulnerable Go symbols the package was found to use; empty for every non-Go match and for
	// module-granularity Go matches where no specific symbol intersection decided the match.
	matchedSymbols := gosymbols.MatchedSymbols(vuln.PackageQualifiers, catalogedPkg)
	// the vulnerability's CPEs relevant at the searched version, surfaced on the CPE match detail
	foundCPEs := matchedCPEsForSearch(catalogedPkg, searchedCPE(criteriaSet), vuln)

	return buildMatchDetails(matcher, distroMatchType, constraintStr, vuln, cpeParams, distroParams, ecosystemParams, matchedSymbols, foundCPEs)
}

// extractSearchParameters processes criteria set and extracts search parameters for different match types
func extractSearchParameters(criteriaSet []vulnerability.Criteria, vuln vulnerability.Vulnerability, catalogedPkg pkg.Package) ([]match.CPEParameters, []match.DistroParameters, []match.EcosystemParameters, *match.PackageParameter) {
	var cpeParams []match.CPEParameters
	var distroParams []match.DistroParameters
	var ecosystemParams []match.EcosystemParameters
	var pkgParams *match.PackageParameter

	for i := range criteriaSet {
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

		case *search.PackageVersionCriteria:
			// the version a search was made at, conveyed without constraining results. Recording it
			// here is what lets Set.SplitVulnerable read each record's own searched version back off
			// its details rather than assuming every record in a set was searched at the same one.
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
					c.CPE.Attributes.String(),
				},
				// CPE searches carry no package-name criterion, so record package identity from the cataloged package
				Package: match.PackageParameter{
					Name:    catalogedPkg.Name,
					Version: catalogedPkg.Version,
				},
			})

		case *search.DistroCriteria:
			for _, d := range c.Distros {
				version := d.VersionString()
				if version == "rolling" { // rolling is a made-up term to find records in the database
					version = ""
				}
				distroParams = append(distroParams, match.DistroParameters{
					Distro: match.DistroIdentification{
						Type:    d.Type.String(),
						Version: version,
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
func buildMatchDetails(
	matcher match.MatcherType, distroMatchType match.Type, constraintStr string, vuln vulnerability.Vulnerability,
	cpeParams []match.CPEParameters, distroParams []match.DistroParameters, ecosystemParams []match.EcosystemParameters,
	matchedSymbols []string, foundCPEs []cpe.CPE,
) match.Details {
	var details match.Details

	// stringify (with proper escaping) and sort the found CPEs for deterministic detail output
	foundCPEStrings := make([]string, 0, len(foundCPEs))
	for _, c := range foundCPEs {
		foundCPEStrings = append(foundCPEStrings, c.Attributes.String())
	}
	sort.Strings(foundCPEStrings)

	// add CPE match details
	for _, cpeParam := range cpeParams {
		details = append(details, match.Detail{
			Type:       match.CPEMatch,
			Matcher:    matcher,
			SearchedBy: cpeParam,
			Found: match.CPEResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: constraintStr,
				CPEs:              foundCPEStrings,
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
				MatchedSymbols:    matchedSymbols,
			},
			Confidence: 1.0, // TODO: this is hard coded for now
		})
	}

	return details
}

// searchedCPE returns the CPE a search was made with, or nil when the criteria hold no CPE search.
func searchedCPE(criteriaSet []vulnerability.Criteria) *cpe.CPE {
	for i := range criteriaSet {
		if c, ok := criteriaSet[i].(*search.CPECriteria); ok {
			return &c.CPE
		}
	}
	return nil
}

// matchedCPEsForSearch returns the vulnerability's CPEs that are relevant at the version the search
// was made with. It is empty when the vulnerability carries no CPEs.
//
// The comparison uses searchedBy's version rather than the package's own. By the time a CPE search
// runs, that version has been put in terms a CPE can be compared against -- an apk's -rN build suffix
// dropped, for one -- and a CPE the search already matched must not then be filtered back out by a
// version its ecosystem happens to spell differently. Without a CPE search there is no searched
// version, and the result is unused anyway: only CPE details carry found CPEs.
func matchedCPEsForSearch(catalogedPkg pkg.Package, searchedBy *cpe.CPE, vuln vulnerability.Vulnerability) []cpe.CPE {
	if len(vuln.CPEs) == 0 {
		return nil
	}

	format := pkg.VersionFormat(catalogedPkg)

	searchVersion := catalogedPkg.Version
	var searchUpdate string
	if searchedBy != nil {
		if v := searchedBy.Attributes.Version; v != "" && v != wfn.Any && v != wfn.NA {
			searchVersion = v
		}
		searchUpdate = searchedBy.Attributes.Update
	}

	if searchVersion == "" {
		// no filtering available by version
		return vuln.CPEs
	}

	pkgVersion := version.New(comparableCPEVersion(searchVersion, searchUpdate, format), format)
	matchedCPEs := make([]cpe.CPE, 0, len(vuln.CPEs))
	for _, c := range vuln.CPEs {
		if c.Attributes.Version == wfn.Any || c.Attributes.Version == wfn.NA {
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		constraint, err := version.GetConstraint(comparableCPEVersion(c.Attributes.Version, c.Attributes.Update, format), format)
		if err != nil {
			// if we can't get a version constraint, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		satisfied, err := constraint.Satisfied(pkgVersion)
		if err != nil || satisfied {
			// if we can't check for version satisfaction, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}
	}

	return matchedCPEs
}

// comparableCPEVersion renders a CPE's version and update fields as one version string the given
// format can be compared against.
func comparableCPEVersion(cpeVersion, cpeUpdate string, format version.Format) string {
	switch format {
	case version.ApkFormat:
		// the searched version is normalized before a CPE search runs, but only when the package's own
		// CPE carried a version -- the fallback to the raw package version is not -- so normalize here
		// rather than relying on where the version came from
		return cpeversion.Alpine(cpeVersion)
	case version.JVMFormat:
		return cpeversion.JVM(cpeVersion, cpeUpdate)
	}
	return cpeVersion
}
