package golang

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherGolang_DropMainPackage(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "istio.io/istio",
		Version: "v0.0.0-20220606222826-f59ce19ec6b6",
		Type:    syftPkg.GoModulePkg,
		Metadata: pkg.GolangBinMetadata{
			MainModule: "istio.io/istio",
		},
	}

	matcher := Matcher{}
	store := newMockProvider()

	actual, _ := matcher.Match(store, nil, p)
	assert.Len(t, actual, 0, "unexpected match count; should not match main module")
}

func newMockProvider() *mockProvider {
	mp := mockProvider{
		data: make(map[syftPkg.Language]map[string][]vulnerability.Vulnerability),
	}

	mp.populateData()

	return &mp
}

type mockProvider struct {
	data map[syftPkg.Language]map[string][]vulnerability.Vulnerability
}

func (mp *mockProvider) Get(id, namespace string) ([]vulnerability.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func (mp *mockProvider) populateData() {
	mp.data[syftPkg.Go] = map[string][]vulnerability.Vulnerability{
		"istio.io/istio": {
			{
				Constraint: version.MustGetConstraint("<5.0.7", version.UnknownFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}
}

func (mp *mockProvider) GetByCPE(p cpe.CPE) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return mp.data[l][p.Name], nil
}
