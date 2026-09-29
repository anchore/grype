package result

import (
	"slices"
	"sort"

	"github.com/facebookincubator/nvdtools/wfn"

	v6 "github.com/anchore/grype/grype/db/v6"
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

	// FindAll includes unaffected records
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
	for _, criteriaSet := range search.CriteriaIterator(criteria) {
		searches, rewritten := searchRewrites(p.vulnProvider, p.catalogedPkg, criteriaSet)
		if !rewritten {
			if err := p.findInto(results, criteriaSet); err != nil {
				return Set{}, err
			}
			continue
		}
		for _, searchCriteria := range searches {
			if err := p.findInto(results, searchCriteria); err != nil {
				return Set{}, err
			}
		}
	}
	return results, nil
}

// findInto adds the results of one search to results.
func (p provider) findInto(results Set, searchCriteria []vulnerability.Criteria) error {
	vulns, err := p.vulnProvider.FindVulnerabilities(searchCriteria...)
	if err != nil {
		return err
	}

	for _, v := range vulns {
		if v.ID == "" {
			continue // skip vulnerabilities without an ID (should never happen)
		}

		details := detailProvider(p.matcher, p.catalogedPkg, searchCriteria, v)

		newResult := Result{
			ID:              v.ID,
			Vulnerabilities: []vulnerability.Vulnerability{v},
			Details:         details,
			Package:         p.searchedPackage(searchCriteria),
			Rank:            rankOf(searchCriteria, details),
		}

		results[v.ID] = append(results[v.ID], newResult)
	}
	return nil
}

// searchRewrites returns the searches to run in place of cs, or false to search cs as is, when the
// provider evaluates search rules (see v6.SearchRuleProvider).
func searchRewrites(vp vulnerability.Provider, catalogedPkg pkg.Package, cs []vulnerability.Criteria) ([][]vulnerability.Criteria, bool) {
	if rp, ok := vp.(v6.SearchRuleProvider); ok {
		return rp.SearchRewrites(catalogedPkg, cs)
	}
	return nil, false
}

func (p provider) FindAll(criteria ...vulnerability.Criteria) (Set, error) {
	affected, err := p.FindResults(criteria...)
	if err != nil {
		return Set{}, err
	}

	unaffected, err := p.FindResults(append(slices.Clone(criteria), search.ForUnaffected())...)
	if err != nil {
		return Set{}, err
	}

	return affected.Merge(unaffected), nil
}

func detailProvider(matcher match.MatcherType, catalogedPkg pkg.Package, criteriaSet []vulnerability.Criteria, vuln vulnerability.Vulnerability) match.Details {
	cpeParams, distroParams, ecosystemParams, pkgParams := extractSearchParameters(criteriaSet, vuln, catalogedPkg)
	distroMatchType := determineMatchType(catalogedPkg, pkgParams, slices.ContainsFunc(criteriaSet, isSourcePackage))
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

		case *search.PackageCriteria:
			// the searched package's version, not the cataloged one (e.g. an upstream's); its name only
			// when no name criterion states one (e.g. a CPE search)
			if pkgParams == nil {
				pkgParams = &match.PackageParameter{}
			}
			pkgParams.Version = c.Package.Version
			if pkgParams.Name == "" {
				pkgParams.Name = c.Package.Name
			}

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

func determineMatchType(catalogedPkg pkg.Package, pkgParams *match.PackageParameter, indirect bool) match.Type {
	if indirect || pkgParams != nil && catalogedPkg.Name != pkgParams.Name {
		return match.ExactIndirectMatch
	}
	return match.ExactDirectMatch
}

func isSourcePackage(c vulnerability.Criteria) bool {
	_, ok := c.(*search.SourcePackageCriteria)
	return ok
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

// searchedPackage returns the package criteriaSet states it searches for (see search.WithPackage),
// else the cataloged package.
func (p provider) searchedPackage(criteriaSet []vulnerability.Criteria) *pkg.Package {
	out := &p.catalogedPkg
	for _, c := range criteriaSet {
		if pc, ok := c.(*search.PackageCriteria); ok {
			searched := pc.Package
			out = &searched
		}
	}
	return out
}
