package internal

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	var matches []match.Match
	var ignored []match.IgnoreFilter

	for _, name := range store.PackageSearchNames(p) {
		nameMatches, nameIgnores, err := MatchPackageByEcosystemPackageName(store, p, name, matcherType)
		if err != nil {
			return nil, nil, err
		}
		matches = append(matches, nameMatches...)
		ignored = append(ignored, nameIgnores...)
	}

	return matches, ignored, nil
}

func MatchPackageByEcosystemPackageName(provider vulnerability.Provider, p pkg.Package, packageName string, matcherType match.MatcherType) ([]match.Match, []match.IgnoreFilter, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	var matches []match.Match
	vulns, err := provider.FindVulnerabilities(
		search.ByEcosystem(p.Language, p.Type),
		search.ByPackageName(packageName),
		OnlyQualifiedPackages(p),
		OnlyVulnerableVersions(version.NewVersionFromPkg(p)),
		OnlyNonWithdrawnVulnerabilities(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("matcher failed to fetch language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	for _, vuln := range vulns {
		matches = append(matches, match.Match{
			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0, // TODO: this is hard coded for now
					Matcher:    matcherType,
					SearchedBy: match.EcosystemParameters{
						Language:  string(p.Language),
						Namespace: vuln.Namespace,
						Package: match.PackageParameter{
							Name:    p.Name,
							Version: p.Version,
						},
					},
					Found: match.EcosystemResult{
						VulnerabilityID:   vuln.ID,
						VersionConstraint: vuln.Constraint.String(),
					},
				},
			},
		})
	}
	return matches, nil, err
}
