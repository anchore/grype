package search

import (
	"fmt"

	"github.com/nextlinux/griffon/griffon/distro"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/vulnerability"
)

func onlyQualifiedPackages(d *distro.Distro, p pkg.Package, allVulns []vulnerability.Vulnerability) ([]vulnerability.Vulnerability, error) {
	var vulns []vulnerability.Vulnerability

	for _, vuln := range allVulns {
		isVulnerable := true

		for _, q := range vuln.PackageQualifiers {
			v, err := q.Satisfied(d, p)

			if err != nil {
				return nil, fmt.Errorf("failed to check package qualifier=%q for distro=%q package=%q: %w", q, d, p, err)
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
