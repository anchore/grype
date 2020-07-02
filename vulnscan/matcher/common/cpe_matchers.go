package common

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

func FindMatchesByPackageCPE(store vulnerability.ProviderByCPE, p *pkg.Package, matcherName string) ([]match.Match, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	matches := make([]match.Match, 0)
	vulnSet := vulnerability.NewSet()

	for _, cpe := range verObj.CPEs() {
		allPkgVulns, err := store.GetByCPE(cpe)
		if err != nil {
			return nil, fmt.Errorf("matcher failed to fetch by CPE pkg='%s': %w", p.Name, err)
		}

		for _, vuln := range allPkgVulns {
			if vulnSet.Contains(vuln) {
				continue
			}
			vulnSet.Add(vuln)

			// if the constraint it met, then the given package has the vulnerability
			isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
			if err != nil {
				return nil, fmt.Errorf("cpe matcher failed to check constraint='%s' version='%s': %w", vuln.Constraint, verObj, err)
			}

			if isPackageVulnerable {
				matches = append(matches, match.Match{
					Type:          match.FuzzyMatch,
					Confidence:    0.9, // TODO: this is hard coded for now
					Vulnerability: *vuln,
					Package:       p,
					Matcher:       matcherName,
					SearchKey:     fmt.Sprintf("cpe[%s] constraint[%s]", cpe.BindToFmtString(), vuln.Constraint.String()),
				})
			}
		}
	}
	return matches, err
}
