package distro

import (
	"strings"

	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/version"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
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
	pr.data["debian:8"] = map[string][]*vulnerability.Vulnerability{
		// direct...
		"neutron": {
			{
				Constraint: version.MustGetConstraint("< 2014.1.5-6", version.DpkgFormat),
				ID:         "CVE-2014-fake-1",
			},
		},
		// indirect...
		"neutron-devel": {
			// expected...
			{
				Constraint: version.MustGetConstraint("< 2014.1.4-5", version.DpkgFormat),
				ID:         "CVE-2014-fake-2",
			},
			{
				Constraint: version.MustGetConstraint("< 2015.0.0-1", version.DpkgFormat),
				ID:         "CVE-2013-fake-3",
			},
			// unexpected...
			{
				Constraint: version.MustGetConstraint("< 2014.0.4-1", version.DpkgFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func (pr *mockProvider) GetByDistro(d distro.Distro, p *pkg.Package) ([]*vulnerability.Vulnerability, error) {
	return pr.data[strings.ToLower(d.Type.String())+":"+d.FullVersion()][p.Name], nil
}
