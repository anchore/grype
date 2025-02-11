package dpkg

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
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
