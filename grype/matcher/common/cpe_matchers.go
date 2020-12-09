package common

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/facebookincubator/nvdtools/wfn"
)

// FindMatchesByPackageCPE retrieves all vulnerabilities that match the generated CPE
func FindMatchesByPackageCPE(store vulnerability.ProviderByCPE, p pkg.Package, upstreamMatcher match.MatcherType) ([]match.Match, error) {
	verObj, err := version.NewVersionFromPkg(p)
	if err != nil {
		return nil, fmt.Errorf("matcher failed to parse version pkg='%s' ver='%s': %w", p.Name, p.Version, err)
	}

	matches := make([]match.Match, 0)
	vulnSet := vulnerability.NewSet()
	vulnerableKeys := internal.NewStringSet()

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
				// create a string key to ensure we aren't adding previously added matches
				vulnerableKey := fmt.Sprintf("%s%s%s", vuln.ID, cpe.BindToFmtString(), vuln.Constraint.String())
				if vulnerableKeys.Contains(vulnerableKey) {
					continue
				}
				vulnerableKeys.Add(vulnerableKey)

				matches = append(matches, match.Match{
					Type:          match.FuzzyMatch,
					Confidence:    0.9, // TODO: this is hard coded for now
					Vulnerability: *vuln,
					Package:       p,
					Matcher:       upstreamMatcher,
					SearchKey: map[string]interface{}{
						"cpe": cpe.BindToFmtString(),
					},
					SearchMatches: map[string]interface{}{
						"cpes":       cpesToString(vuln.CPEs),
						"constraint": vuln.Constraint.String(),
					},
				})
			}
		}
	}
	return matches, err
}

// cpesToString receives one or more CPEs and stringifies them
func cpesToString(cpes []wfn.Attributes) []string {
	var stringers = make([]string, 0)
	for _, cpe := range cpes {
		stringers = append(stringers, cpe.BindToFmtString())
	}

	return stringers
}
