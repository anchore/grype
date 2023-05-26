package search

import (
	"errors"
	"fmt"

	"github.com/nextlinux/griffon/griffon/version"
	"github.com/nextlinux/griffon/griffon/vulnerability"
	"github.com/nextlinux/griffon/internal/log"
)

func onlyVulnerableVersions(verObj *version.Version, allVulns []vulnerability.Vulnerability) ([]vulnerability.Vulnerability, error) {
	var vulns []vulnerability.Vulnerability

	for _, vuln := range allVulns {
		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
		if err != nil {
			var e *version.NonFatalConstraintError
			if errors.As(err, &e) {
				log.Warn(e)
			} else {
				return nil, fmt.Errorf("failed to check constraint=%q version=%q: %w", vuln.Constraint, verObj, err)
			}
		}

		if !isPackageVulnerable {
			continue
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
