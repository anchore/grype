package apk

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Matcher behaves a little differently here than its other implementations.
// Secdb provides a negative match to the NVD matches meaning it can only be
// used to turn off a vulnerability. The contraint is a lie. Only the "fixed_in_versions"
// Column shows the true match to turn off...
//
// Example....
/*
-----------------------------
Package Match in NVD:
zlib: v1.2.3-r2  |  CVE X — affected versions: < v1.4.2

Secdb data shows
zlib: v1.2.3-r2 fixes CVE X

Expected result:
Match is not reported because of the Secdb fix
*/
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

	// direct matches with package
	cpeMatches, err := m.cpeMatchesWithoutSecDBFixes(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, cpeMatches...)

	// indirect matches with package source
	indirectMatches, err := m.matchBySourceIndirection(store, d, p)
	if err != nil {
		return nil, err
	}
	matches = append(matches, indirectMatches...)

	return matches, nil
}

// compares NVD matches against secdb fixes for a given distro
func (m *Matcher) cpeMatchesWithoutSecDBFixes(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, err := search.ByPackageCPE(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatchesByID := matchesByID(cpeMatches)

	// get all secDB fixes for the provided distro
	secDBVulnFixes, err := store.GetByDistro(d, p)
	if err != nil {
		return nil, err
	}

	secDBFixesByID := fixesByID(secDBVulnFixes)

	// remove cpe matches where there is an entry in the secDB for the particular package-vulnerability pairing
	// and the installed package version should match the fixed in version for the secDB record.
	var finalCpeMatches []match.Match

cveLoop:
	for id, cpeMatchesForID := range cpeMatchesByID {
		// check to see if there is a secdb entry for this ID (CVE)
		secDBFixForID, exists := secDBFixesByID[id]
		if !exists {
			// does not exist in secdb, so the CPE record(s) should be added to the final results
			finalCpeMatches = append(finalCpeMatches, cpeMatchesForID...)
			continue
		}

		// there is a secdb entry...
		for _, vuln := range secDBFixForID {
			// ...is there a fixed in entry? (should always be yes)
			if len(vuln.Fix.Versions) == 0 {
				continue
			}

			// ...is the current package vulnerable?
			vulnerable := true
			for _, fixedVersion := range vuln.Fix.Versions {
				// we found that the packages version is the same
				// as the fixed version for the given CVE in secdb
				if fixedVersion == p.Version {
					vulnerable = false
					break
				}
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

func matchesByID(matches []match.Match) map[string][]match.Match {
	var results = make(map[string][]match.Match)
	for _, secDBMatch := range matches {
		results[secDBMatch.Vulnerability.ID] = append(results[secDBMatch.Vulnerability.ID], secDBMatch)
	}
	return results
}

func fixesByID(vulnFixes []vulnerability.Vulnerability) map[string][]vulnerability.Vulnerability {
	var results = make(map[string][]vulnerability.Vulnerability)
	for _, vuln := range vulnFixes {
		results[vuln.ID] = append(results[vuln.ID], vuln)
	}

	return results
}

func (m *Matcher) matchBySourceIndirection(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	var matches []match.Match

	for _, indirectPackage := range pkg.UpstreamPackages(p) {
		// direct matches with package
		indirectMatches, err := m.cpeMatchesWithoutSecDBFixes(store, d, indirectPackage)
		if err != nil {
			return nil, err
		}
		matches = append(matches, indirectMatches...)
	}

	// we want to make certain that we are tracking the match based on the package from the SBOM (not the indirect package)
	// however, we also want to keep the indirect package around for future reference
	match.ConvertToIndirectMatches(matches, p)

	return matches, nil
}
