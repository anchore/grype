package internal

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
	var matches []match.Match
	var ignored []match.IgnoredMatch

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

func MatchPackageByEcosystemPackageName(store vulnerability.Provider, p pkg.Package, packageName string, matcherType match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil, nil
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	var matches []match.Match
	vulns, err := store.FindVulnerabilities(
		search.ByEcosystem(p.Language, p.Type),
		search.ByPackageName(packageName),
		onlyQualifiedPackages(p),
		onlyVulnerableVersions(verObj),
		onlyNonWithdrawnVulnerabilities(),
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
					SearchedBy: map[string]interface{}{
						"language":  string(p.Language),
						"namespace": vuln.Namespace,
						"package": map[string]string{
							"name":    p.Name,
							"version": p.Version,
						},
					},
					Found: map[string]interface{}{
						"vulnerabilityID":   vuln.ID,
						"versionConstraint": vuln.Constraint.String(),
					},
				},
			},
		})
	}
	return matches, nil, err
}
