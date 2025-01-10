package search

import (
	"errors"
	"fmt"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

func ByPackageLanguage(store vulnerability.Provider, p pkg.Package, matcherType match.MatcherType) ([]match.Match, error) {
	if isUnknownVersion(p.Version) {
		log.WithFields("package", p.Name).Trace("skipping package with unknown version")
		return nil, nil
	}

	// if p.Language == "" {
	//	log.WithFields("package", p.Name).Trace("skipping package with unknown language")
	//	return nil, nil
	//}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		if errors.Is(err, version.ErrUnsupportedVersion) {
			log.WithFields("error", err).Tracef("skipping package '%s@%s'", p.Name, p.Version)
			return nil, nil
		}
		return nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	vulns, err := store.FindVulnerabilities(
		db.ByLanguage(p.Language),
		db.ByPackageName(p.Name),
		onlyQualifiedPackages(p),
		onlyVulnerableVersions(verObj),
	)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	var matches []match.Match
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

	return matches, err
}
