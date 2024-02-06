package golang

import (
	"testing"

	"github.com/google/uuid"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_DropMainPackage(t *testing.T) {

	mainModuleMetadata := pkg.GolangBinMetadata{
		MainModule: "istio.io/istio",
	}

	subjectWithoutMainModule := pkg.Package{
		ID:       pkg.ID(uuid.NewString()),
		Name:     "istio.io/istio",
		Version:  "v0.0.0-20220606222826-f59ce19ec6b6",
		Type:     syftPkg.GoModulePkg,
		Language: syftPkg.Go,
		Metadata: pkg.GolangBinMetadata{},
	}

	subjectWithMainModule := subjectWithoutMainModule
	subjectWithMainModule.Metadata = mainModuleMetadata

	subjectWithMainModuleAsDevel := subjectWithMainModule
	subjectWithMainModuleAsDevel.Version = "(devel)"

	matcher := NewGolangMatcher(MatcherConfig{})
	store := newMockProvider()

	preTest, _ := matcher.Match(store, nil, subjectWithoutMainModule)
	assert.Len(t, preTest, 1, "should have matched the package when there is not a main module")

	actual, _ := matcher.Match(store, nil, subjectWithMainModule)
	assert.Len(t, actual, 0, "unexpected match count; should not match main module")

	actual, _ = matcher.Match(store, nil, subjectWithMainModuleAsDevel)
	assert.Len(t, actual, 0, "unexpected match count; should not match main module (devel)")
}

func TestMatcher_SearchForStdlib(t *testing.T) {

	// values derived from:
	//   $ go version -m $(which grype)
	//  /opt/homebrew/bin/grype: go1.21.1

	subject := pkg.Package{
		ID:       pkg.ID(uuid.NewString()),
		Name:     "stdlib",
		Version:  "go1.18.3",
		Type:     syftPkg.GoModulePkg,
		Language: syftPkg.Go,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:golang:go:1.18.3:-:*:*:*:*:*:*", ""),
		},
		Metadata: pkg.GolangBinMetadata{},
	}

	cases := []struct {
		name         string
		cfg          MatcherConfig
		subject      pkg.Package
		expectedCVEs []string
	}{
		// positive
		{
			name: "cpe enables, no override enabled",
			cfg: MatcherConfig{
				UseCPEs:               true,
				AlwaysUseCPEForStdlib: false,
			},
			subject: subject,
			expectedCVEs: []string{
				"CVE-2022-27664",
			},
		},
		{
			name: "stdlib search, cpe enables, no override enabled",
			cfg: MatcherConfig{
				UseCPEs:               true,
				AlwaysUseCPEForStdlib: true,
			},
			subject: subject,
			expectedCVEs: []string{
				"CVE-2022-27664",
			},
		},
		{
			name: "stdlib search, cpe enables, no override enabled",
			cfg: MatcherConfig{
				UseCPEs:               false,
				AlwaysUseCPEForStdlib: true,
			},
			subject: subject,
			expectedCVEs: []string{
				"CVE-2022-27664",
			},
		},
		{
			name: "go package search should be found by cpe",
			cfg: MatcherConfig{
				UseCPEs:               true,
				AlwaysUseCPEForStdlib: true,
			},
			subject: func() pkg.Package { p := subject; p.Name = "go"; return p }(),
			expectedCVEs: []string{
				"CVE-2022-27664",
			}},
		// negative
		{
			name: "stdlib search, cpe suppressed, no override enabled",
			cfg: MatcherConfig{
				UseCPEs:               false,
				AlwaysUseCPEForStdlib: false,
			},
			subject:      subject,
			expectedCVEs: nil,
		},
		{
			name: "go package search should not be an exception (only the stdlib)",
			cfg: MatcherConfig{
				UseCPEs:               false,
				AlwaysUseCPEForStdlib: true,
			},
			subject:      func() pkg.Package { p := subject; p.Name = "go"; return p }(),
			expectedCVEs: nil,
		},
	}

	store := newMockProvider()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matcher := NewGolangMatcher(c.cfg)

			actual, _ := matcher.Match(store, nil, c.subject)
			actualCVEs := strset.New()
			for _, m := range actual {
				actualCVEs.Add(m.Vulnerability.ID)
			}

			expectedCVEs := strset.New(c.expectedCVEs...)

			assert.ElementsMatch(t, expectedCVEs.List(), actualCVEs.List())

		})
	}

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
		// for TestMatcher_DropMainPackage
		"istio.io/istio": {
			{
				Constraint: version.MustGetConstraint("< 5.0.7", version.UnknownFormat),
				ID:         "CVE-2013-fake-BAD",
			},
		},
	}

	mp.data["nvd:cpe"] = map[string][]vulnerability.Vulnerability{
		// for TestMatcher_SearchForStdlib
		"cpe:2.3:a:golang:go:1.18.3:-:*:*:*:*:*:*": {
			{
				Constraint: version.MustGetConstraint("< 1.18.6 || = 1.19.0", version.UnknownFormat),
				ID:         "CVE-2022-27664",
			},
		},
	}
}

func (mp *mockProvider) GetByCPE(p cpe.CPE) ([]vulnerability.Vulnerability, error) {
	return mp.data["nvd:cpe"][p.Attributes.BindToFmtString()], nil
}

func (mp *mockProvider) GetByDistro(d *distro.Distro, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return []vulnerability.Vulnerability{}, nil
}

func (mp *mockProvider) GetByLanguage(l syftPkg.Language, p pkg.Package) ([]vulnerability.Vulnerability, error) {
	return mp.data[l][p.Name], nil
}
