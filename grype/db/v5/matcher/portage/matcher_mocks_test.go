package portage

import (
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

func newMockProvider() *db.MockProvider {
	return db.NewMockProvider([]vulnerability.Vulnerability{
		// direct...
		{
			PackageName: "app-misc/neutron",
			Constraint:  version.MustGetConstraint("< 2014.1.3", version.PortageFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-1", Namespace: "secdb:distro:gentoo:"},
		},
		{
			PackageName: "app-misc/neutron",
			Constraint:  version.MustGetConstraint("< 2014.1.4", version.PortageFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2014-fake-2", Namespace: "secdb:distro:gentoo:"},
		},
	}...)
}
