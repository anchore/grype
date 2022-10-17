package search

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

func onlyQualifiedPackages(p pkg.Package, allVulns []vulnerability.Vulnerability) ([]vulnerability.Vulnerability, error) {
	var vulns []vulnerability.Vulnerability

	for _, vuln := range allVulns {
		isVulnerable := true

		for _, q := range vuln.PackageQualifiers {
			v, err := q.Satisfied(p)

			if err != nil {
				return nil, fmt.Errorf("failed to check package qualifier=%q for package=%q: %w", q, p, err)
			}

			isVulnerable = v
			if !isVulnerable {
				break
			}
		}

		if !isVulnerable {
			continue
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
