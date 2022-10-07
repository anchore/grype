package search

import (
	"github.com/facebookincubator/nvdtools/wfn"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Determines if a vulnerability is an accurate match using the vulnerability's cpes' target software
func onlyVulnerableTargets(p pkg.Package, allVulns []vulnerability.Vulnerability) []vulnerability.Vulnerability {
	var vulns []vulnerability.Vulnerability

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
			targetSW := cpe.TargetSW
			mismatchWithUnknownLanguage := targetSW != string(p.Language) && syftPkg.LanguageByName(targetSW) == syftPkg.UnknownLanguage
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
