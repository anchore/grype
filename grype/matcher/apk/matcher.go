package apk

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct {
}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.ApkPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.ApkMatcher
}

func (m *Matcher) Match(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches = make([]match.Match, 0)

	// direct matches with package itself
	directMatches, err := m.findMatchesForPackage(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, directMatches...)

	// indirect matches, via package's origin package
	indirectMatches, err := m.findMatchesForOriginPackage(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, indirectMatches...)

	return matches, nil
}

//nolint:funlen
func (m *Matcher) cpeMatchesWithoutSecDBFixes(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, err := search.ByPackageCPE(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatchesByID := matchesByID(cpeMatches)

	// remove cpe matches where there is an entry in the secDB for the particular package-vulnerability pairing, and the
	// installed package version is >= the fixed in version for the secDB record.
	secDBVulnerabilities, err := store.GetByDistro(d, p)
	if err != nil {
		return nil, err
	}

	for _, upstreamPkg := range pkg.UpstreamPackages(p) {
		secDBVulnerabilitiesForUpstream, err := store.GetByDistro(d, upstreamPkg)
		if err != nil {
			return nil, err
		}
		secDBVulnerabilities = append(secDBVulnerabilities, secDBVulnerabilitiesForUpstream...)
	}

	secDBVulnerabilitiesByID := vulnerabilitiesByID(secDBVulnerabilities)

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil
		}
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	var finalCpeMatches []match.Match

cveLoop:
	for id, cpeMatchesForID := range cpeMatchesByID {
		// check to see if there is a secdb entry for this ID (CVE)
		secDBVulnerabilitiesForID, exists := secDBVulnerabilitiesByID[id]
		if !exists {
			// does not exist in secdb, so the CPE record(s) should be added to the final results

			// remove fixed-in versions, since NVD doesn't know when Alpine will fix things
			for _, nvdOnlyMatch := range cpeMatchesForID {
				if len(nvdOnlyMatch.Vulnerability.Fix.Versions) > 0 {
					nvdOnlyMatch.Vulnerability.Fix = vulnerability.Fix{
						State: vulnerability.FixStateUnknown,
					}
				}
				finalCpeMatches = append(finalCpeMatches, nvdOnlyMatch)
			}
			continue
		}

		// there is a secdb entry...
		for _, vuln := range secDBVulnerabilitiesForID {
			// ...is there a fixed in entry? (should always be yes)
			if len(vuln.Fix.Versions) == 0 {
				continue
			}

			// ...is the current package vulnerable?
			vulnerable, err := vuln.Constraint.Satisfied(verObj)
			if err != nil {
				return nil, err
			}

			if vulnerable {
				// if there is at least one vulnerable entry, then all CPE record(s) should be added to the final results
				finalCpeMatches = append(finalCpeMatches, cpeMatchesForID...)
				continue cveLoop
			}
		}
	}
	return finalCpeMatches, nil
}

func deduplicateMatches(secDBMatches, cpeMatches []match.Match) (matches []match.Match) {
	// add additional unique matches from CPE source that is unique from the SecDB matches
	secDBMatchesByID := matchesByID(secDBMatches)
	cpeMatchesByID := matchesByID(cpeMatches)
	for id, cpeMatchesForID := range cpeMatchesByID {
		// by this point all matches have been verified to be vulnerable within the given package version relative to the vulnerability source.
		// now we will add unique CPE candidates that were not found in secdb.
		if _, exists := secDBMatchesByID[id]; !exists {
			// add the new CPE-based record (e.g. NVD) since it was not found in secDB
			matches = append(matches, cpeMatchesForID...)
		}
	}
	return matches
}

func matchesByID(matches []match.Match) map[string][]match.Match {
	var results = make(map[string][]match.Match)
	for _, secDBMatch := range matches {
		results[secDBMatch.Vulnerability.ID] = append(results[secDBMatch.Vulnerability.ID], secDBMatch)
	}
	return results
}

func vulnerabilitiesByID(vulns []vulnerability.Vulnerability) map[string][]vulnerability.Vulnerability {
	var results = make(map[string][]vulnerability.Vulnerability)
	for _, vuln := range vulns {
		results[vuln.ID] = append(results[vuln.ID], vuln)
	}

	return results
}

func (m *Matcher) findMatchesForPackage(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find SecDB matches for the given package name and version
	secDBMatches, err := search.ByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	// TODO: are there other errors that we should handle here that causes this to short circuit
	cpeMatches, err := m.cpeMatchesWithoutSecDBFixes(store, d, p)
	if err != nil && !errors.Is(err, search.ErrEmptyCPEMatch) {
		return nil, err
	}

	var matches []match.Match

	// keep all secdb matches, as this is an authoritative source
	matches = append(matches, secDBMatches...)

	// keep only unique CPE matches
	matches = append(matches, deduplicateMatches(secDBMatches, cpeMatches)...)

	return matches, nil
}

func (m *Matcher) findMatchesForOriginPackage(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		indirectMatches, err := m.findMatchesForPackage(store, d, indirectPackage)
		if err != nil {
			return nil, fmt.Errorf("failed to find vulnerabilities for apk upstream source package: %w", err)
		}
		matches = append(matches, indirectMatches...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}
