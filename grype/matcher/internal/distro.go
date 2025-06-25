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

func MatchPackageByDistro(provider vulnerability.Provider, p pkg.Package, refPkg *pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if p.Distro == nil {
		return nil, nil, nil
	}

	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	var matches []match.Match
	vulns, err := provider.FindVulnerabilities(
		search.ByPackageName(p.Name),
		search.ByDistro(*p.Distro),
		OnlyQualifiedPackages(p),
		OnlyVulnerableVersions(version.NewVersionFromPkg(p)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", p.Distro, p.Name, err)
	}

	ty := match.ExactIndirectMatch
	if refPkg == nil {
		ty = match.ExactDirectMatch
		refPkg = &p
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       *refPkg,
			Details: []match.Detail{
				{
					Type:    ty,
					Matcher: upstreamMatcher,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    p.Distro.Type.String(),
							Version: p.Distro.Version,
						},
						Package: match.PackageParameter{
							Name:    p.Name,
							Version: p.Version,
						},
						Namespace: vuln.Namespace,
					},
					Found: match.DistroResult{
						VulnerabilityID:   vuln.ID,
						VersionConstraint: vuln.Constraint.String(),
					},
					Confidence: 1.0, // TODO: this is hard coded for now
				},
			},
		})
	}
	return matches, nil, err
}

func isUnknownVersion(v string) bool {
	return strings.ToLower(v) == "unknown"
}
