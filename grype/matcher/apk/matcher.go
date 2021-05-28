package apk

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
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

	// find Alpine SecDB matches for the given package name and version
	secDbMatches, err := common.FindMatchesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatches, err := m.cpeMatchesWithoutSecDbFixes(store, d, p)
	if err != nil {
		return nil, err
	}

	// keep all secdb matches, as this is an authoritative source
	matches = append(matches, secDbMatches...)

	// keep only unique CPE matches
	matches = append(matches, deduplicateMatches(secDbMatches, cpeMatches)...)

	return matches, nil
}

func (m *Matcher) cpeMatchesWithoutSecDbFixes(store vulnerability.Provider, d *distro.Distro, p pkg.Package) ([]match.Match, error) {
	// find CPE-indexed vulnerability matches specific to the given package name and version
	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}

	cpeMatchesByID := matchesByID(cpeMatches)

	// remove cpe matches where there is an entry in the secDB for the particular package-vulnerability pairing, and the
	// installed package version is >= the fixed in version for the secDB record.
	secDbVulnerabilities, err := store.GetByDistro(*d, p)
	if err != nil {
		return nil, err
	}

	secDbVulnerabilitiesByID := vulnerabilitiesByID(secDbVulnerabilities)

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	var finalCpeMatches []match.Match

cveLoop:
	for id, cpeMatchesForID := range cpeMatchesByID {
		// check to see if there is a secdb entry for this ID (CVE)
		secDbVulnerabilitiesForID, exists := secDbVulnerabilitiesByID[id]
		if !exists {
			// does not exist in secdb, so the CPE record(s) should be added to the final results
			finalCpeMatches = append(finalCpeMatches, cpeMatchesForID...)
			continue
		}

		// there is a secdb entry...
		for _, vuln := range secDbVulnerabilitiesForID {
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

func deduplicateMatches(secDbMatches, cpeMatches []match.Match) (matches []match.Match) {
	// add additional unique matches from CPE source that is unique from the SecDB matches
	secDbMatchesByID := matchesByID(secDbMatches)
	cpeMatchesByID := matchesByID(cpeMatches)
	for id, cpeMatchesForID := range cpeMatchesByID {
		// by this point all matches have been verified to be vulnerable within the given package version relative to the vulnerability source.
		// now we will add unique CPE candidates that were not found in secdb.
		if _, exists := secDbMatchesByID[id]; !exists {
			// add the new CPE-based record (e.g. NVD) since it was not found in secDB
			matches = append(matches, cpeMatchesForID...)
		}
	}
	return matches
}

func matchesByID(matches []match.Match) map[string][]match.Match {
	var results = make(map[string][]match.Match)
	for _, secDbMatch := range matches {
		results[secDbMatch.Vulnerability.ID] = append(results[secDbMatch.Vulnerability.ID], secDbMatch)
	}
	return results
}

func vulnerabilitiesByID(vulns []*vulnerability.Vulnerability) map[string][]*vulnerability.Vulnerability {
	var results = make(map[string][]*vulnerability.Vulnerability)
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		results[vuln.ID] = append(results[vuln.ID], vuln)
	}

	return results
}
