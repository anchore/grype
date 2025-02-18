package internal

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
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

// MatchPackageByCPEs retrieves all vulnerabilities that match any of the provided package's CPEs
func MatchPackageByCPEs(store vulnerability.Provider, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	// we attempt to merge match details within the same matcher when searching by CPEs, in this way there are fewer duplicated match
	// objects (and fewer duplicated match details).

	// Warn the user if they are matching by CPE, but there are no CPEs available.
	if len(p.CPEs) == 0 {
		return nil, ErrEmptyCPEMatch
	}

	matchesByFingerprint := make(map[match.Fingerprint]match.Match)
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

		format := version.FormatFromPkg(p)

		if format == version.JVMFormat {
			searchVersion = transformJvmVersion(searchVersion, c.Attributes.Update)
		}

		verObj, err := version.NewVersion(searchVersion, format)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
		}

		// find all vulnerability records in the DB for the given CPE (not including version comparisons)
		vulns, err := store.FindVulnerabilities(
			search.ByCPE(c),
			onlyVulnerableTargets(p),
			onlyQualifiedPackages(p),
			onlyVulnerableVersions(verObj),
			onlyNonWithdrawnVulnerabilities(),
		)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to fetch by CPE pkg=%q: %w", p.Name, err)
		}

		// for each vulnerability record found, check the version constraint. If the constraint is satisfied
		// relative to the current version information from the CPE (or the package) then the given package
		// is vulnerable.
		for _, vuln := range vulns {
			addNewMatch(matchesByFingerprint, vuln, p, *verObj, upstreamMatcher, c)
		}
	}

	return toMatches(matchesByFingerprint), nil
}

func transformJvmVersion(searchVersion, updateCpeField string) string {
	// we should take into consideration the CPE update field for JVM packages
	if strings.HasPrefix(searchVersion, "1.") && !strings.Contains(searchVersion, "_") && updateCpeField != wfn.NA && updateCpeField != wfn.Any {
		searchVersion = fmt.Sprintf("%s_%s", searchVersion, strings.TrimPrefix(updateCpeField, "update"))
	}
	return searchVersion
}

func addNewMatch(matchesByFingerprint map[match.Fingerprint]match.Match, vuln vulnerability.Vulnerability, p pkg.Package, searchVersion version.Version, upstreamMatcher match.MatcherType, searchedByCPE cpe.CPE) {
	candidateMatch := match.Match{

		Vulnerability: vuln,
		Package:       p,
	}

	if existingMatch, exists := matchesByFingerprint[candidateMatch.Fingerprint()]; exists {
		candidateMatch = existingMatch
	}

	candidateMatch.Details = addMatchDetails(candidateMatch.Details,
		match.Detail{
			Type:       match.CPEMatch,
			Confidence: 0.9, // TODO: this is hard coded for now
			Matcher:    upstreamMatcher,
			SearchedBy: match.CPEParameters{
				Namespace: vuln.Namespace,
				CPEs: []string{
					searchedByCPE.Attributes.BindToFmtString(),
				},
				Package: match.CPEPackageParameter{
					Name:    p.Name,
					Version: p.Version,
				},
			},
			Found: match.CPEResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: vuln.Constraint.String(),
				CPEs:              cpesToString(filterCPEsByVersion(searchVersion, vuln.CPEs)),
			},
		},
	)

	matchesByFingerprint[candidateMatch.Fingerprint()] = candidateMatch
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

func filterCPEsByVersion(pkgVersion version.Version, allCPEs []cpe.CPE) (matchedCPEs []cpe.CPE) {
	for _, c := range allCPEs {
		if c.Attributes.Version == wfn.Any || c.Attributes.Version == wfn.NA {
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		ver := c.Attributes.Version

		if pkgVersion.Format == version.JVMFormat {
			if c.Attributes.Update != wfn.Any && c.Attributes.Update != wfn.NA {
				ver = transformJvmVersion(ver, c.Attributes.Update)
			}
		}

		constraint, err := version.GetConstraint(ver, pkgVersion.Format)
		if err != nil {
			// if we can't get a version constraint, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}

		satisfied, err := constraint.Satisfied(&pkgVersion)
		if err != nil || satisfied {
			// if we can't check for version satisfaction, don't filter out the CPE
			matchedCPEs = append(matchedCPEs, c)
			continue
		}
	}
	return matchedCPEs
}

func toMatches(matchesByFingerprint map[match.Fingerprint]match.Match) (matches []match.Match) {
	for _, m := range matchesByFingerprint {
		matches = append(matches, m)
	}
	sort.Sort(match.ByElements(matches))
	return matches
}

// cpesToString receives one or more CPEs and stringifies them
func cpesToString(cpes []cpe.CPE) []string {
	var strs = make([]string, len(cpes))
	for idx, c := range cpes {
		strs[idx] = c.Attributes.BindToFmtString()
	}
	sort.Strings(strs)
	return strs
}
