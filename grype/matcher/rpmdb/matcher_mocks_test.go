package rpmdb

import (
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
)

type mockProvider struct {
	data map[string]map[string][]*vulnerability.Vulnerability
}

func newMockProvider() *mockProvider {
	pr := mockProvider{
		data: make(map[string]map[string][]*vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockProvider) stub() {
	pr.data["rhel:8"] = map[string][]*vulnerability.Vulnerability{
		// direct...
		"neutron-libs": {
			{
				Constraint: version.MustGetConstraint("<= 7.1.3-6", version.RpmFormat),
				ID:         "CVE-2014-fake-1",
			},
		},
		// indirect...
		"neutron": {
			// expected...
			{
				Constraint: version.MustGetConstraint("< 7.1.4-5", version.RpmFormat),
				ID:         "CVE-2014-fake-2",
			},
			{
				Constraint: version.MustGetConstraint("< 8.0.2-0", version.RpmFormat),
				ID:         "CVE-2013-fake-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint("< 7.0.4-1", version.RpmFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func (pr *mockProvider) GetByDistro(d distro.Distro, p pkg.Package) ([]*vulnerability.Vulnerability, error) {
	var ty = strings.ToLower(d.Type.String())
	if d.Type == distro.CentOS || d.Type == distro.RedHat {
		ty = "rhel"
	}

	return pr.data[ty+":"+d.FullVersion()][p.Name], nil
}
