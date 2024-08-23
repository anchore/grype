package search

import (
	"errors"
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/internal/log"
)

func onlyWithinAffectedVersionRange(pkgVer *version.Version, all []v6.AffectedPackageHandle) ([]v6.AffectedPackageHandle, error) {
	var filtered []v6.AffectedPackageHandle

	for i, a := range all {
		keep, err := isWithinAffectedVersionRange(pkgVer, a)
		if err != nil {
			return nil, err
		}

		if !keep {
			continue
		}

		filtered = append(filtered, all[i])
	}

	return filtered, nil
}

func isWithinAffectedVersionRange(pkgVer *version.Version, a v6.AffectedPackageHandle) (bool, error) {
	if a.BlobValue == nil {
		return false, nil
	}

	for _, r := range a.BlobValue.Ranges {

		c, err := version.GetConstraint(r.Version.Constraint, version.ParseFormat(r.Version.Type))
		if err != nil {
			return false, fmt.Errorf("failed to parse constraint=%q: %w", r.Version.Constraint, err)
		}

		s, err := c.Satisfied(pkgVer)
		if err != nil {
			var e *version.NonFatalConstraintError
			if errors.As(err, &e) {
				log.Warn(e)
			} else {
				return false, fmt.Errorf("failed to check constraint=%q version=%q: %w", r.Version.Constraint, pkgVer, err)
			}
		}

		if !s {
			return false, nil
		}

	}

	return true, nil
}

//func onlyVulnerableVersions(verObj *version.Version, allVulns []vulnerability.Vulnerability) ([]vulnerability.Vulnerability, error) {
//	var vulns []vulnerability.Vulnerability
//
//	for _, vuln := range allVulns {
//		isPackageVulnerable, err := vuln.Constraint.Satisfied(verObj)
//		if err != nil {
//			var e *version.NonFatalConstraintError
//			if errors.As(err, &e) {
//				log.Warn(e)
//			} else {
//				return nil, fmt.Errorf("failed to check constraint=%q version=%q: %w", vuln.Constraint, verObj, err)
//			}
//		}
//
//		if !isPackageVulnerable {
//			continue
//		}
//
//		vulns = append(vulns, vuln)
//	}
//
//	return vulns, nil
//}
