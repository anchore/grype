package golang

import (
	"testing"

	"github.com/google/uuid"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcher_DropMainPackageGivenVersionInfo(t *testing.T) {
	tests := []struct {
		name                         string
		subjectWithoutMainModule     pkg.Package
		mainModuleData               pkg.GolangBinMetadata
		allowPsuedoVersionComparison bool
		expectedMatchCount           int
	}{
		{
			name: "main module with version is matched when pseudo version comparison is allowed",
			subjectWithoutMainModule: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "istio.io/istio",
				Version:  "v0.0.0-20220606222826-f59ce19ec6b6",
				Type:     syftPkg.GoModulePkg,
				Language: syftPkg.Go,
				Metadata: pkg.GolangBinMetadata{},
			},
			mainModuleData: pkg.GolangBinMetadata{
				MainModule: "istio.io/istio",
			},
			allowPsuedoVersionComparison: true,
			expectedMatchCount:           1,
		},
		{
			name: "main module with version is NOT matched when pseudo version comparison is disabled",
			subjectWithoutMainModule: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "istio.io/istio",
				Version:  "v0.0.0-20220606222826-f59ce19ec6b6",
				Type:     syftPkg.GoModulePkg,
				Language: syftPkg.Go,
				Metadata: pkg.GolangBinMetadata{},
			},
			mainModuleData: pkg.GolangBinMetadata{
				MainModule: "istio.io/istio",
			},
			allowPsuedoVersionComparison: false,
			expectedMatchCount:           0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mainModuleMetadata := test.mainModuleData
			subjectWithoutMainModule := test.subjectWithoutMainModule

			subjectWithMainModule := subjectWithoutMainModule
			subjectWithMainModule.Metadata = mainModuleMetadata

			subjectWithMainModuleAsDevel := subjectWithMainModule
			subjectWithMainModuleAsDevel.Version = "(devel)"

			matcher := NewGolangMatcher(MatcherConfig{
				AllowMainModulePseudoVersionComparison: test.allowPsuedoVersionComparison,
			})
			store := newMockProvider()

			preTest, _, _ := matcher.Match(store, subjectWithoutMainModule)
			assert.Len(t, preTest, 1, "should have matched the package when there is not a main module")

			actual, _, _ := matcher.Match(store, subjectWithMainModule)
			assert.Len(t, actual, test.expectedMatchCount, "should match the main module depending on config (i.e. 1 match)")

			actual, _, _ = matcher.Match(store, subjectWithMainModuleAsDevel)
			assert.Len(t, actual, 0, "unexpected match count; should never match main module (devel)")
		})
	}
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

			actual, _, _ := matcher.Match(store, c.subject)
			actualCVEs := strset.New()
			for _, m := range actual {
				actualCVEs.Add(m.Vulnerability.ID)
			}

			expectedCVEs := strset.New(c.expectedCVEs...)

			assert.ElementsMatch(t, expectedCVEs.List(), actualCVEs.List())

		})
	}
}

func newMockProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		// for TestMatcher_DropMainPackageIfNoVersion
		{
			PackageName: "istio.io/istio",
			Constraint:  version.MustGetConstraint("< 5.0.7", version.UnknownFormat),
			Reference:   vulnerability.Reference{ID: "CVE-2013-fake-BAD", Namespace: "github:language:" + syftPkg.Go.String()},
		},
		{
			CPEs:       []cpe.CPE{cpe.Must("cpe:2.3:a:golang:go:1.18.3:-:*:*:*:*:*:*", "test")},
			Constraint: version.MustGetConstraint("< 1.18.6 || = 1.19.0", version.UnknownFormat),
			Reference:  vulnerability.Reference{ID: "CVE-2022-27664", Namespace: "nvd:cpe"},
		},
	}...)
}
