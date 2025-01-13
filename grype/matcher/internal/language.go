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

func MatchPackageByLanguage(store vulnerability.Provider, p pkg.Package, packageNames func(pkg.Package) []string, matcherType match.MatcherType) ([]match.Match, []match.IgnoredMatch, error) {
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
	for _, packageName := range packageNames(p) {
		vulns, err := store.FindVulnerabilities(
			search.ByLanguage(p.Language),
			search.ByPackageName(packageName),
			onlyQualifiedPackages(p),
			onlyVulnerableVersions(verObj),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("matcher failed to fetch language=%q pkg=%q: %w", p.Language, packageName, err)
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
								"name":    p.Name, // FIXME this should probably be packageName; retained existing behavior
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
	}
	return matches, nil, err
}
