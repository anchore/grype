package common

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindMatchesForPackage(allPkgVulns []*vulnerability.Vulnerability, p *pkg.Package, matcherName string) ([]match.Match, error) {
	matches := make([]match.Match, 0)
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			// TODO: not enough information (cannot back track constraint object)
			return nil, fmt.Errorf("language matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
		}

		if isPackageVulnerable {
			matches = append(matches, match.Match{
				Type:          match.ExactDirectMatch,
				Confidence:    1.0, // TODO: this is hard coded for now
				Vulnerability: *vuln,
				Package:       p,
				Matcher:       matcherName,
			})
		}
	}
	return matches, nil
}
