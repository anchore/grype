package common

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
)

func FindMatchesByPackageDistro(store vulnerability.ProviderByDistro, d *distro.Distro, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	if d == nil {
		return nil, nil
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	var allPkgVulns []*vulnerability.Vulnerability

	allPkgVulns, err = store.GetByDistro(*d, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro='%s' pkg='%s': %w", d, p.Name, err)
	}

	matches := make([]match.Match, 0)
	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			return nil, fmt.Errorf("distro matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
		}

		if isPackageVulnerable {
			matches = append(matches, match.Match{
				Type:          match.ExactDirectMatch,
				Confidence:    1.0, // TODO: this is hard coded for now
				Vulnerability: *vuln,
				Package:       p,
				Matcher:       upstreamMatcher,
				SearchKey: map[string]interface{}{
					"distro": map[string]string{
						"type":    d.Type.String(),
						"version": d.RawVersion,
					},
				},
				SearchMatches: map[string]interface{}{
					"constraint": vuln.Constraint.String(),
				},
			})
		}
	}

	return matches, err
}
