package pacman

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/internal"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher struct{}

func (m *Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{syftPkg.AlpmPkg}
}

func (m *Matcher) Type() match.MatcherType {
	return match.PacmanMatcher
}

func (m *Matcher) Match(vp vulnerability.Provider, p pkg.Package) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match

	// For Arch Linux, we match directly against the package
	exactMatches, err := m.findMatches(vp, p)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find vulnerabilities for pacman package: %w", err)
	}

	matches = append(matches, exactMatches...)

	return matches, nil, nil
}

func (m *Matcher) findMatches(vp vulnerability.Provider, searchPkg pkg.Package) ([]match.Match, error) {
	if searchPkg.Distro == nil {
		return nil, nil
	}

	if isUnknownVersion(searchPkg.Version) {
		log.WithFields("package", searchPkg.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	// Find vulnerabilities for this package within the Arch Linux distro
	vulns, err := vp.FindVulnerabilities(
		search.ByPackageName(searchPkg.Name),
		search.ByDistro(*searchPkg.Distro),
		internal.OnlyQualifiedPackages(searchPkg),
		internal.OnlyVulnerableVersions(version.New(searchPkg.Version, pkg.VersionFormat(searchPkg))),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro=%q pkg=%q: %w", searchPkg.Distro, searchPkg.Name, err)
	}

	var matches []match.Match
	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       searchPkg,
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: m.Type(),
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
					Confidence: 1.0,
				},
			},
		})
	}

	return matches, nil
}

func isUnknownVersion(v string) bool {
	return v == "" || strings.ToLower(v) == "unknown"
}
