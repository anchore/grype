package search

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func ByPackageLanguage(store vulnerability.ProviderByLanguage, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg=%q ver=%q: %w", p.Name, p.Version, err)
	}

	allPkgVulns, err := store.GetByLanguage(p.Language, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch language=%q pkg=%q: %w", p.Language, p.Name, err)
	}

	applicableVulns, err := onlyQualifiedPackages(p, allPkgVulns)
	if err != nil {
		return nil, fmt.Errorf("unable to filter language-related vulnerabilities: %w", err)
	}

	// TODO: Port this over to a qualifier and remove
	applicableVulns, err = onlyVulnerableVersions(verObj, applicableVulns)
	if err != nil {
		return nil, fmt.Errorf("unable to filter language-related vulnerabilities: %w", err)
	}

	var matches []match.Match
	for _, vuln := range applicableVulns {
		matches = append(matches, match.Match{

			Vulnerability: vuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0, // TODO: this is hard coded for now
					Matcher:    upstreamMatcher,
					SearchedBy: map[string]interface{}{
						"language":  string(p.Language),
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
