package rpm

import (
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg/qualifier"
	"github.com/anchore/grype/grype/pkg/qualifier/rpmmodularity"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftCpe "github.com/anchore/syft/syft/cpe"
)

func newMockProvider(packageName, indirectName string, withEpoch bool, withPackageQualifiers bool) vulnerability.Provider {
	if withEpoch {
		return mock.VulnerabilityProvider(vulnerabilitiesWithEpoch(packageName, indirectName)...)
	} else if withPackageQualifiers {
		return mock.VulnerabilityProvider(vulnerabilitiesWithPackageQualifiers(packageName)...)
	}
	return mock.VulnerabilityProvider(vulnerabilitiesDefaults(packageName, indirectName)...)
}

const namespace = "secdb:distro:centos:8"

func vulnerabilitiesDefaults(packageName, indirectName string) []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		// direct...
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 7.1.3-6", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-1", Namespace: namespace},
		},
		// indirect...
		// expected...
		{
			PackageName: indirectName,
			Constraint:  version.MustGetConstraint("< 7.1.4-5", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: namespace},
		},
		{
			PackageName: indirectName,
			Constraint:  version.MustGetConstraint("< 8.0.2-0", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-3", Namespace: namespace},
		},
		// unexpected...
		{
			PackageName: indirectName,
			Constraint:  version.MustGetConstraint("< 7.0.4-1", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-BAD", Namespace: namespace},
		},
	}
}

func vulnerabilitiesWithEpoch(packageName, indirectName string) []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		// direct...
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-1", Namespace: namespace},
		},
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:2.28-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-2", Namespace: namespace},
		},
		// indirect...
		{
			PackageName: indirectName,
			Constraint:  version.MustGetConstraint("< 5.28.3-420.el8", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-3", Namespace: namespace},
		},
		// unexpected...
		{
			PackageName: indirectName,
			Constraint:  version.MustGetConstraint("< 4:5.26.3-419.el8", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-4", Namespace: namespace},
		},
	}
}

func vulnerabilitiesWithPackageQualifiers(packageName string) []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		// direct...
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-1", Namespace: namespace},
			PackageQualifiers: []qualifier.Qualifier{
				rpmmodularity.New("containertools:3"),
			},
		},
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-2", Namespace: namespace},
			PackageQualifiers: []qualifier.Qualifier{
				rpmmodularity.New(""),
			},
		},
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-3", Namespace: namespace},
		},
		{
			PackageName: packageName,
			Constraint:  version.MustGetConstraint("<= 0:1.0-419.el8.", version.RpmFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2021-4", Namespace: namespace},
			PackageQualifiers: []qualifier.Qualifier{
				rpmmodularity.New("containertools:4"),
			},
		},
	}
}

// mockEOLProvider wraps mock.VulnerabilityProvider and adds EOLChecker support for testing
type mockEOLProvider struct {
	vulnerability.Provider
	eolDate *time.Time
}

func (m *mockEOLProvider) GetOperatingSystemEOL(d *distro.Distro) (eolDate, eoasDate *time.Time, err error) {
	return m.eolDate, nil, nil
}

func newMockEOLProvider(eolDate *time.Time) *mockEOLProvider {
	// include CPE vulnerability for testing CPE fallback
	return &mockEOLProvider{
		Provider: mock.VulnerabilityProvider([]vulnerability.Vulnerability{
			// distro-based vulnerability
			{
				PackageName: "openssl",
				Reference:   vulnerability.Reference{ID: "CVE-2014-distro-1", Namespace: namespace},
				Constraint:  version.MustGetConstraint("< 1.0.2", version.RpmFormat),
			},
			// CPE-based vulnerability
			{
				PackageName: "openssl",
				Reference:   vulnerability.Reference{ID: "CVE-2014-cpe-1", Namespace: "nvd:cpe"},
				Constraint:  version.MustGetConstraint("< 1.0.2", version.UnknownFormat),
				CPEs: []syftCpe.CPE{
					syftCpe.Must("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", ""),
				},
			},
		}...),
		eolDate: eolDate,
	}
}
