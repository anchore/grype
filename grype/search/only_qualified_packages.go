package search

import (
	"fmt"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/platformcpe"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
)

func onlyQualifiedAffectedPackages(d *distro.Distro, p pkg.Package, all []v6.AffectedPackageHandle) ([]v6.AffectedPackageHandle, error) {
	var filtered []v6.AffectedPackageHandle

	for i, a := range all {
		keep, err := isPackageQualified(d, p, a.BlobValue)
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

func isPackageQualified(d *distro.Distro, p pkg.Package, a *v6.AffectedBlob) (bool, error) {
	if a == nil {
		return false, nil
	}

	var qualifiers []qualifier.Qualifier
	for _, c := range a.PlatformCPEs {
		qualifiers = append(qualifiers, platformcpe.New(c))
	}

	if a.RpmModularity != "" {
		qualifiers = append(qualifiers, rpmmodularity.New(a.RpmModularity))
	}

	for _, q := range qualifiers {
		v, err := q.Satisfied(d, p)

		if err != nil {
			return false, fmt.Errorf("failed to check package qualifier=%q for distro=%q package=%q: %w", q, d, p, err)
		}

		if !v {
			return false, nil
		}
	}
	return true, nil
}

//func onlyQualifiedPackages(d *distro.Distro, p pkg.Package, allVulns []vulnerability.Vulnerability) ([]vulnerability.Vulnerability, error) {
//	var vulns []vulnerability.Vulnerability
//
//	for _, vuln := range allVulns {
//		isVulnerable := true
//
//		for _, q := range vuln.PackageQualifiers {
//			v, err := q.Satisfied(d, p)
//
//			if err != nil {
//				return nil, fmt.Errorf("failed to check package qualifier=%q for distro=%q package=%q: %w", q, d, p, err)
//			}
//
//			isVulnerable = v
//			if !isVulnerable {
//				break
//			}
//		}
//
//		if !isVulnerable {
//			continue
//		}
//
//		vulns = append(vulns, vuln)
//	}
//
//	return vulns, nil
//}
