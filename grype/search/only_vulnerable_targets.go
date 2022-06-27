package search

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/facebookincubator/nvdtools/wfn"
)

//Determines if a vulnerability is an accurate match using the vulnerability's cpes' target software
func onlyVulnerableTargets(p pkg.Package, allVulns []vulnerability.Vulnerability) []vulnerability.Vulnerability {
	var vulns []vulnerability.Vulnerability

	for _, vuln := range allVulns {
		isPackageVulnerable := len(vuln.CPEs) != 0
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
