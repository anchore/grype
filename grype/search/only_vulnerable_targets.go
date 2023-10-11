package search

import (
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func isOSPackage(p pkg.Package) bool {
	return p.Type == syftPkg.AlpmPkg || p.Type == syftPkg.ApkPkg || p.Type == syftPkg.DebPkg || p.Type == syftPkg.KbPkg || p.Type == syftPkg.PortagePkg || p.Type == syftPkg.RpmPkg
}

func isUnknownTarget(targetSW string) bool {
	if syftPkg.LanguageByName(targetSW) != syftPkg.UnknownLanguage {
		return false
	}

	// There are some common target software CPE components which are not currently
	// supported by syft but are signifcant sources of false positives and should be
	// considered known for the purposes of filtering here
	known := map[string]bool{
		"joomla":    true,
		"joomla\\!": true,
		"drupal":    true,
	}

	if _, ok := known[targetSW]; ok {
		return false
	}

	return true
}

// Determines if a vulnerability is an accurate match using the vulnerability's cpes' target software
func onlyVulnerableTargets(p pkg.Package, allVulns []vulnerability.Vulnerability) []vulnerability.Vulnerability {
	var vulns []vulnerability.Vulnerability

	// Exclude OS package types from this logic, since they could be embedding any type of ecosystem package
	if isOSPackage(p) {
		return allVulns
	}

	// There are quite a few cases within java where other ecosystem components (particularly javascript packages)
	// are embedded directly within jar files, so we can't yet make this assumption with java as it will cause dropping
	// of valid vulnerabilities that syft has specific logic https://github.com/anchore/syft/blob/main/syft/pkg/cataloger/common/cpe/candidate_by_package_type.go#L48-L75
	// to ensure will be surfaced
	if p.Language == syftPkg.Java {
		return allVulns
	}

	for _, vuln := range allVulns {
		isPackageVulnerable := len(vuln.CPEs) == 0
		for _, cpe := range vuln.CPEs {
			targetSW := cpe.Attributes.TargetSW
			mismatchWithUnknownLanguage := targetSW != string(p.Language) && isUnknownTarget(targetSW)
			if targetSW == wfn.Any || targetSW == wfn.NA || targetSW == string(p.Language) || mismatchWithUnknownLanguage {
				isPackageVulnerable = true
			}
		}

		if !isPackageVulnerable {
			continue
		}

		vulns = append(vulns, vuln)
	}

	return vulns
}
