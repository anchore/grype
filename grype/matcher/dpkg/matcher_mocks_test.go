package dpkg

import (
	"time"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftCpe "github.com/anchore/syft/syft/cpe"
)

func newMockProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			PackageName: "neutron",
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-1", Namespace: "secdb:distro:debian:8"},
			Constraint:  version.MustGetConstraint("< 2014.1.3-6", version.DebFormat),
		},
		// expected...
		{
			PackageName: "neutron-devel",
			Constraint:  version.MustGetConstraint("< 2014.1.4-5", version.DebFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: "secdb:distro:debian:8"},
		},
		{
			PackageName: "neutron-devel",
			Constraint:  version.MustGetConstraint("< 2015.0.0-1", version.DebFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-3", Namespace: "secdb:distro:debian:8"},
		},
		// unexpected...
		{
			PackageName: "neutron-devel",
			Constraint:  version.MustGetConstraint("< 2014.0.4-1", version.DebFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-BAD", Namespace: "secdb:distro:debian:8"},
		},
	}...)
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
				Reference:   vulnerability.Reference{ID: "CVE-2014-distro-1", Namespace: "secdb:distro:debian:8"},
				Constraint:  version.MustGetConstraint("< 1.0.2", version.DebFormat),
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
