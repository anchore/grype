package java

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type mockProvider struct {
	data map[string]map[string][]vulnerability.Vulnerability
}

func newMockProvider() *mockProvider {
	pr := mockProvider{
		data: make(map[string]map[string][]vulnerability.Vulnerability),
	}

	return &pr
}

func (pr *mockProvider) GetByCPE(p syftPkg.CPE) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (pr *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (pr *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}
