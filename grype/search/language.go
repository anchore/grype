package search

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func MatchesByPackageLanguage(store vulnerability.ProviderByLanguage, l syftPkg.Language, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	allPkgVulns, err := store.GetByLanguage(l, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch language='%s' pkg='%s': %w", l, p.Name, err)
	}

	matches := make([]match.Match, 0)
	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			return nil, fmt.Errorf("language matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
		}

		if !isPackageVulnerable {
			continue
		}

		matches = append(matches, match.Match{

			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0, // TODO: this is hard coded for now
					Matcher:    upstreamMatcher,
					SearchedBy: map[string]interface{}{
						"language":  l.String(),
						"namespace": vuln.Namespace,
					},
					Found: map[string]interface{}{
						"versionConstraint": vuln.Constraint.String(),
					},
				},
			},
		})
	}

	return matches, err
}
