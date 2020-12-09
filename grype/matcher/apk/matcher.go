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
	var secDbCandidates = make(map[string][]match.Match)

	// find Alpine SecDB matches for the given package name and version
	secDbMatches, err := common.FindMatchesByPackageDistro(store, d, p, m.Type())
	if err != nil {
		return nil, err
	}

	for _, secDbMatch := range secDbMatches {
		secDbCandidates[secDbMatch.Vulnerability.ID] = append(secDbCandidates[secDbMatch.Vulnerability.ID], secDbMatch)
	}

	// find NVD matches specific to the given package name and version
	var cpeCandidates = make(map[string][]match.Match)
	cpeMatches, err := common.FindMatchesByPackageCPE(store, p, m.Type())
	if err != nil {
		return nil, err
	}

	for _, cpeMatch := range cpeMatches {
		cpeCandidates[cpeMatch.Vulnerability.ID] = append(cpeCandidates[cpeMatch.Vulnerability.ID], cpeMatch)
	}

	// package is vulnerable if there is a match in the alpine SecDB and NVD for the same CVE
	for cve, cpeCandidatesForCve := range cpeCandidates {
		// by this point all matches have been verified to be vulnerable within the given package version relative to the vulnerability source
		_, ok := secDbCandidates[cve]
		if ok {
			// this is a match, use the NVD records as the primary record source (no need to merge)
			matches = append(matches, cpeCandidatesForCve...)
		}
	}

	return matches, nil
}
