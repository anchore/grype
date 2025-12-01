package common

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func FilterRootIoUnaffectedMatches(store vulnerability.Provider, p pkg.Package, matches []match.Match) []match.Match {
	if len(matches) == 0 || p.Distro == nil {
		return matches
	}

	rootIOCriteria := search.RootIOCriteria{
		DistroName:    p.Distro.Name(),
		DistroVersion: p.Distro.VersionString(),
	}

	unaffectedPkgs, err := store.FindUnaffectedPackages(p, rootIOCriteria)
	if err != nil {
		log.WithFields("package", p.Name, "error", err).Debug("failed to query unaffected packages")
		return matches
	}

	if len(unaffectedPkgs) == 0 {
		return matches
	}

	unaffectedCVEs := make(map[string]vulnerability.UnaffectedPackage)
	for _, up := range unaffectedPkgs {
		unaffectedCVEs[up.CVE] = up
	}

	versionFormat := pkg.VersionFormat(p)

	var filteredMatches []match.Match
	for _, m := range matches {
		up, isUnaffected := unaffectedCVEs[m.Vulnerability.ID]
		if !isUnaffected {
			filteredMatches = append(filteredMatches, m)
			continue
		}

		matched, err := up.Matches(p.Version, versionFormat)
		if err != nil {
			log.WithFields("package", p.Name, "version", p.Version, "constraint", up.Constraint, "error", err).
				Debug("failed to check unaffected constraint")
			filteredMatches = append(filteredMatches, m)
			continue
		}

		if matched {
			log.WithFields("package", p.Name, "version", p.Version, "cve", m.Vulnerability.ID, "constraint", up.Constraint).
				Debug("filtered Root.io unaffected vulnerability")
		} else {
			filteredMatches = append(filteredMatches, m)
		}
	}

	return filteredMatches
}

func FilterRootIoUnaffectedMatchesForLanguage(store vulnerability.Provider, p pkg.Package, language string, matches []match.Match) []match.Match {
	return FilterRootIoUnaffectedMatches(store, p, matches)
}
