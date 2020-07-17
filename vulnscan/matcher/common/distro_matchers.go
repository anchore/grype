// nolint:dupl
package common

import (
	"fmt"

	"github.com/anchore/vulnscan/vulnscan/version"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindMatchesByPackageDistro(store vulnerability.ProviderByDistro, d distro.Distro, p *pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	allPkgVulns, err := store.GetByDistro(d, p)
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
				SearchKey:     fmt.Sprintf("distro[%s] constraint[%s]", d, vuln.Constraint.String()),
			})
		}
	}

	return matches, err
}
