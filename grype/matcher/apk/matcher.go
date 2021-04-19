package apk

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/common"
	"github.com/anchore/grype/grype/pkg"
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

	// map {  CVE string : []match }
	var secDbMatchesByID = make(map[string][]match.Match)

	// find Alpine SecDB matches for the given package name and version
	secDbMatches, err := common.FindMatchesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	// treat all secdb matches as final matches
	matches = append(matches, secDbMatches...)

	// we need to track which CVEs were added to filter out duplicate NVD matches later
	for _, secDbMatch := range secDbMatches {
		secDbMatchesByID[secDbMatch.Vulnerability.ID] = append(secDbMatchesByID[secDbMatch.Vulnerability.ID], secDbMatch)
	}

	// find NVD matches specific to the given package name and version
	// map {  CVE string : []match }
	var cpeMatchesByID = make(map[string][]match.Match)

	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}

	for _, cpeMatch := range cpeMatches {
		cpeMatchesByID[cpeMatch.Vulnerability.ID] = append(cpeMatchesByID[cpeMatch.Vulnerability.ID], cpeMatch)
	}

	// all secDB matches have been added, new we will add additional unique matches from CPE source (NVD et al.)
	for id, cpeMatch := range cpeMatchesByID {
		// by this point all matches have been verified to be vulnerable within the given package version relative to the vulnerability source.
		// now we will add unique CPE candidates that were not found in secdb.
		if _, exists := secDbMatchesByID[id]; !exists {
			// add the new CPE-based record (e.g. NVD) since it was not found in secDB
			matches = append(matches, cpeMatch...)
		}
	}

	return matches, nil
}
