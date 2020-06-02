package distro

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func ExactPackageNameMatch(store vulnerability.Provider, o distro.Distro, p *pkg.Package, matcherName string) ([]match.Match, error) {
	matches := make([]match.Match, 0)

	// TODO: there should be a vulnerability object in the vulnscan-db/db/vulnerability for mondel serialization and one here in vulnerability for rich objects

	allPkgVulns, err := store.GetByDistro(o, p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to fetch distro='%s' pkg='%s': %w", o, p.Name, err)
	}

	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	for _, vuln := range allPkgVulns {
		// if the constraint it met, then the given package has the vulnerability
		satisfied, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			// TODO: not enough information (cannot back track constraint object)
			return nil, fmt.Errorf("matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
		}

		if satisfied {
			matches = append(matches, match.Match{
				Type:          match.ExactDirectMatch,
				Confidence:    1.0, // TODO: this is hard coded for now
				Vulnerability: *vuln,
				Package:       p,
				// signifies that we have a match from a search by exact package name and version
				SearchKey: fmt.Sprintf("%s:%s", p.Name, p.Version),
				Matcher:   matcherName,
			})
		}
	}
	return matches, nil
}
