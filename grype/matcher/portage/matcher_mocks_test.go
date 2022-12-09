package portage

import (
	"strings"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockProvider struct {
	data map[string]map[string][]vulnerability.Vulnerability
}

func (pr *mockProvider) Get(id, namespace string) ([]vulnerability.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func newMockProvider() *mockProvider {
	pr := mockProvider{
		data: make(map[string]map[string][]vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockProvider) stub() {
	pr.data["gentoo:"] = map[string][]vulnerability.Vulnerability{
		// direct...
		"app-misc/neutron": {
			{
				Constraint: version.MustGetConstraint("< 2014.1.3", version.PortageFormat),
				ID:         "CVE-2014-fake-1",
			},
			{
				Constraint: version.MustGetConstraint("< 2014.1.4", version.PortageFormat),
				ID:         "CVE-2014-fake-2",
			},
		},
	}
}

func (pr *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return pr.data[strings.ToLower(d.Type.String())+":"+d.FullVersion()][p.Name], nil
}

func (pr *mockProvider) GetByCPE(request syftPkg.CPE) (v []vulnerability.Vulnerability, err error) {
	return v, err
}

func (pr *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) (v []vulnerability.Vulnerability, err error) {
	return v, err
}
