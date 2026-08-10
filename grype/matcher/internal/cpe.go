package internal

import (
	"errors"
	"fmt"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal/result"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func alpineCPEComparableVersion(version string) string {
	// clean the alpine package version so that it compares correctly with the CPE version comparison logic
	// alpine versions are suffixed with -r{buildindex}; however, if left intact CPE comparison logic will
	// incorrectly treat these as a pre-release.  In actuality, we just want to treat 1.2.3-r21 as equivalent to
	// 1.2.3 for purposes of CPE-based matching since the alpine fix should filter out any cases where a later
	// build fixes something that was vulnerable in 1.2.3
	components := strings.Split(version, "-r")
	cpeComparableVersion := version

	if len(components) == 2 {
		cpeComparableVersion = components[0]
	}

	return cpeComparableVersion
}

var ErrEmptyCPEMatch = errors.New("attempted CPE match against package with no CPEs")

// MatchPackageByCPEs retrieves all vulnerabilities that match any of the provided package's CPEs,
// returned as a flat slice of matches. It is a thin wrapper over FindResultsByCPEs for callers that
// work in []match.Match rather than result.Set.
func MatchPackageByCPEs(vulnProvider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	results, ignore, err := FindResultsByCPEs(vulnProvider, p, upstreamMatcher)
	if err != nil {
		return nil, nil, err
	}

	return results.ToMatches(), ignore, nil
}

// FindResultsByCPEs retrieves all vulnerabilities that match any of the provided package's CPEs as a
// result.Set, so callers can reconcile them against other sources by vulnerability identity. Records
// the CPE search finds but whose version is not affected are returned as "CPE not vulnerable" ignores.
//
//nolint:funlen
func FindResultsByCPEs(vulnProvider vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) (result.Set, []match.IgnoreFilter, error) {
	provider := result.NewProvider(vulnProvider, p, upstreamMatcher)

	affected := result.Set{}
	var ignores []match.IgnoreFilter
	// we attempt to merge match details within the same matcher when searching by CPEs, in this way there are fewer duplicated match
	// objects (and fewer duplicated match details).

	// Warn the user if they are matching by CPE, but there are no CPEs available.
	if len(p.CPEs) == 0 {
		return nil, nil, ErrEmptyCPEMatch
	}

	for _, c := range p.CPEs {
		// prefer the CPE version, but if npt specified use the package version
		searchVersion := c.Attributes.Version

		if p.Type == syftPkg.ApkPkg {
			searchVersion = alpineCPEComparableVersion(searchVersion)
		}

		if searchVersion == wfn.NA || searchVersion == wfn.Any || isUnknownVersion(searchVersion) {
			searchVersion = p.Version
		}

		if isUnknownVersion(searchVersion) {
			log.WithFields("package", p.Name).Trace("skipping package with unknown version")
			continue
		}

		// we should always show the exact CPE we searched by, not just what's in the component analysis (since we
		// may alter the version based on above processing)
		c.Attributes.Version = searchVersion

		format := pkg.VersionFormat(p)

		if format == version.JVMFormat {
			searchVersion = transformJvmVersion(searchVersion, c.Attributes.Update)
		}

		var verObj *version.Version
		var err error
		if searchVersion != "" {
			verObj = version.New(searchVersion, format)
		}

		criteria := []vulnerability.Criteria{
			search.ByCPE(c),
			OnlyVulnerableTargets(p),
			OnlyQualifiedPackages(p),
			OnlyNonWithdrawnVulnerabilities(),
		}

		versionCriteria := OnlyVulnerableVersions(verObj)

		// find all vulnerability records in the DB for the given CPE (not including version comparisons)
		all, err := provider.FindResults(criteria...)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch by CPE pkg=%q: %w", p.Name, err)
		}

		vulns := all.Filter(versionCriteria)

		unaffected, err := provider.FindResults(
			append(criteria, search.ForUnaffected(), versionCriteria)...,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch unaffected CPE records for pkg=%q: %w", p.Name, err)
		}

		// add affected vulns to top level set, collapsing records that share a match fingerprint (the same
		// vulnerability found via multiple CPEs of this package) into one record with unioned CPE details.
		affected = affected.Merge(vulns, mergeCPEResultsByFingerprint(p))
		// mark unaffected as ignores
		unaffected = all.Remove(vulns).Merge(unaffected)
		ignores = append(ignores, OwnershipIgnores(p, "CPE not vulnerable", unaffected.Vulnerabilities()...)...)
	}

	return affected, ignores, nil
}

// mergeCPEResultsByFingerprint is a result.Set merge function that collapses result records sharing a
// match.Fingerprint into a single record, unioning their CPE details. It is the result.Set equivalent
// of main's matchesByFingerprint + addMatchDetails: a vulnerability found via several of the package's
// CPEs becomes one record whose CPE detail lists every CPE that matched.
func mergeCPEResultsByFingerprint(p pkg.Package) func(existing, incoming []result.Result) []result.Result {
	return func(existing, incoming []result.Result) []result.Result {
		byFingerprint := map[match.Fingerprint]int{}
		var out []result.Result
		for _, r := range append(append([]result.Result(nil), existing...), incoming...) {
			for _, v := range r.Vulnerabilities {
				candidateMatch := match.Match{Vulnerability: v, Package: p}
				fingerprint := candidateMatch.Fingerprint()
				if i, exists := byFingerprint[fingerprint]; exists {
					for _, d := range r.Details {
						out[i].Details = addMatchDetails(out[i].Details, d)
					}
					continue
				}
				byFingerprint[fingerprint] = len(out)
				out = append(out, result.Result{
					ID:              r.ID,
					Package:         r.Package,
					Vulnerabilities: []vulnerability.Vulnerability{v},
					Details:         append([]match.Detail(nil), r.Details...),
				})
			}
		}
		return out
	}
}

func transformJvmVersion(searchVersion, updateCpeField string) string {
	// we should take into consideration the CPE update field for JVM packages
	if strings.HasPrefix(searchVersion, "1.") && !strings.Contains(searchVersion, "_") && updateCpeField != wfn.NA && updateCpeField != wfn.Any {
		searchVersion = fmt.Sprintf("%s_%s", searchVersion, strings.TrimPrefix(updateCpeField, "update"))
	}
	return searchVersion
}

func addMatchDetails(existingDetails []match.Detail, newDetails match.Detail) []match.Detail {
	newFound, ok := newDetails.Found.(match.CPEResult)
	if !ok {
		return existingDetails
	}

	newSearchedBy, ok := newDetails.SearchedBy.(match.CPEParameters)
	if !ok {
		return existingDetails
	}
	for idx, detail := range existingDetails {
		found, ok := detail.Found.(match.CPEResult)
		if !ok {
			continue
		}

		searchedBy, ok := detail.SearchedBy.(match.CPEParameters)
		if !ok {
			continue
		}

		if !found.Equals(newFound) {
			continue
		}

		err := searchedBy.Merge(newSearchedBy)
		if err != nil {
			continue
		}

		existingDetails[idx].SearchedBy = searchedBy
		return existingDetails
	}

	// could not merge with another entry, append to the end
	existingDetails = append(existingDetails, newDetails)
	return existingDetails
}
