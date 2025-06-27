package internal

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackage(searchPkg pkg.Package, refPkg *pkg.Package) pkg.Package {
	if refPkg != nil {
		return *refPkg
	}
	return searchPkg
}

func MatchPackageByDistro(provider vulnerability.Provider, searchPkg pkg.Package, refPkg *pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if searchPkg.Distro == nil {
		return nil, nil, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	var matches []match.Match
	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		OnlyQualifiedPackages(searchPkg),
		OnlyVulnerableVersions(version.NewVersionFromPkg(searchPkg)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       MatchPackage(searchPkg, refPkg),
			Details:       DistroMatchDetails(upstreamMatcher, searchPkg, refPkg, vuln),
		})
	}
	return matches, nil, err
}

func DistroMatchDetails(upstreamMatcher match.MatcherType, searchPkg pkg.Package, refPkg *pkg.Package, vuln vulnerability.Vulnerability) []match.Detail {
	ty := match.ExactIndirectMatch
	if refPkg == nil {
		ty = match.ExactDirectMatch
		refPkg = &searchPkg
	}

	return []match.Detail{
		{
			Type:    ty,
			Matcher: upstreamMatcher,
			SearchedBy: match.DistroParameters{
				Distro: match.DistroIdentification{
					Type:    searchPkg.Distro.Type.String(),
					Version: searchPkg.Distro.Version,
				},
				Package: match.PackageParameter{
					Name:    searchPkg.Name,
					Version: searchPkg.Version,
				},
				Namespace: vuln.Namespace,
			},
			Found: match.DistroResult{
				VulnerabilityID:   vuln.ID,
				VersionConstraint: vuln.Constraint.String(),
			},
			Confidence: 1.0, // TODO: this is hard coded for now
		},
	}
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
