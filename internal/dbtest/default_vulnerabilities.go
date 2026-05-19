package dbtest

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

func DefaultVulnerabilities() []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2024-1234",
				Namespace: "nvd:cpe",
			},
			PackageName:       "asdf",
			Constraint:        version.MustGetConstraint("< 1.4", version.ApkFormat),
			PackageQualifiers: nil,
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:stuff:asdf:*:*:*:*:*:*:*:*", cpe.DeclaredSource),
			},
			Fix: vulnerability.Fix{
				Versions: []string{"1.4.0"},
				State:    vulnerability.FixStateFixed,
			},
			Advisories:             []vulnerability.Advisory{},
			RelatedVulnerabilities: nil,
		},
	}
}
