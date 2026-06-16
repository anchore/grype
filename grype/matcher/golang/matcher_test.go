package golang

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// pseudoVersion is a Go pseudo-version older than every fixed version in
// the istio.io/istio GHSA-fgw5-hp8f-xfhc range, so the matcher should
// flag a normal package as vulnerable. The same value also drives the
// main-module suppression path because the matcher inspects the "v0.0.0-"
// prefix.
const pseudoVersion = "v0.0.0-20220606222826-f59ce19ec6b6"

// TestMatcher_DropMainPackageGivenVersionInfo verifies the special-case
// behavior for Go binaries' main module: when the package is the main
// module of a binary and its version is a Go pseudo-version (or the
// "(devel)" sentinel), the matcher refuses to compare versions unless
// AllowMainModulePseudoVersionComparison is enabled. The fixture's istio
// GHSA covers the test pseudo-version, so the same data exercises both
// the "did match" and "intentionally suppressed" paths under different
// matcher configs.
func TestMatcher_DropMainPackageGivenVersionInfo(t *testing.T) {
	tests := []struct {
		name                       string
		allowPseudoVersionCompare  bool
		expectMainModuleSuppressed bool
	}{
		{
			name:                       "pseudo version is matched on main module when comparison is allowed",
			allowPseudoVersionCompare:  true,
			expectMainModuleSuppressed: false,
		},
		{
			name:                       "pseudo version is suppressed on main module when comparison is disabled",
			allowPseudoVersionCompare:  false,
			expectMainModuleSuppressed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbtest.DBs(t, "istio-and-stdlib").
				SelectOnly("github:go/GHSA-fgw5-hp8f-xfhc").
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewGolangMatcher(MatcherConfig{
						AllowMainModulePseudoVersionComparison: tt.allowPseudoVersionCompare,
					})

					// not the main module - matches regardless of config
					nonMain := dbtest.NewPackage("istio.io/istio", pseudoVersion, syftPkg.GoModulePkg).
						WithLanguage(syftPkg.Go).
						WithMetadata(pkg.GolangBinMetadata{}).
						Build()
					db.Match(t, matcher, nonMain).
						SelectMatch("GHSA-fgw5-hp8f-xfhc").
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()

					// is the main module - config controls suppression
					asMain := dbtest.NewPackage("istio.io/istio", pseudoVersion, syftPkg.GoModulePkg).
						WithLanguage(syftPkg.Go).
						WithMetadata(pkg.GolangBinMetadata{MainModule: "istio.io/istio"}).
						Build()
					if tt.expectMainModuleSuppressed {
						db.Match(t, matcher, asMain).IsEmpty()
					} else {
						db.Match(t, matcher, asMain).
							SelectMatch("GHSA-fgw5-hp8f-xfhc").
							SelectDetailByType(match.ExactDirectMatch).
							AsEcosystemSearch()
					}

					// "(devel)" main module is always suppressed regardless of config
					asDevelMain := dbtest.NewPackage("istio.io/istio", "(devel)", syftPkg.GoModulePkg).
						WithLanguage(syftPkg.Go).
						WithMetadata(pkg.GolangBinMetadata{MainModule: "istio.io/istio"}).
						Build()
					db.Match(t, matcher, asDevelMain).IsEmpty()
				})
		})
	}
}

// TestMatcher_SearchForStdlib verifies the CPE-search behavior gated by
// MatcherConfig.UseCPEs and AlwaysUseCPEForStdlib. The Go matcher
// otherwise restricts itself to ecosystem-name lookups; CPE-based lookups
// are reserved for the stdlib because the standard library is the only
// Go module that NVD tracks via CPE (golang:go).
func TestMatcher_SearchForStdlib(t *testing.T) {
	stdlib := func(name string) pkg.Package {
		return dbtest.NewPackage(name, "go1.18.3", syftPkg.GoModulePkg).
			WithLanguage(syftPkg.Go).
			WithCPE("cpe:2.3:a:golang:go:1.18.3:-:*:*:*:*:*:*").
			WithMetadata(pkg.GolangBinMetadata{}).
			Build()
	}

	cases := []struct {
		name       string
		cfg        MatcherConfig
		pkg        pkg.Package
		expectHit  bool
		expectCVEs []string
	}{
		{
			name:       "cpe enabled, no override",
			cfg:        MatcherConfig{UseCPEs: true, AlwaysUseCPEForStdlib: false},
			pkg:        stdlib("stdlib"),
			expectHit:  true,
			expectCVEs: []string{"CVE-2022-27664"},
		},
		{
			name:       "cpe enabled, stdlib override on",
			cfg:        MatcherConfig{UseCPEs: true, AlwaysUseCPEForStdlib: true},
			pkg:        stdlib("stdlib"),
			expectHit:  true,
			expectCVEs: []string{"CVE-2022-27664"},
		},
		{
			name:       "cpe disabled, stdlib override on",
			cfg:        MatcherConfig{UseCPEs: false, AlwaysUseCPEForStdlib: true},
			pkg:        stdlib("stdlib"),
			expectHit:  true,
			expectCVEs: []string{"CVE-2022-27664"},
		},
		{
			name:       "package named go (not stdlib) with override on - cpe enabled",
			cfg:        MatcherConfig{UseCPEs: true, AlwaysUseCPEForStdlib: true},
			pkg:        stdlib("go"),
			expectHit:  true,
			expectCVEs: []string{"CVE-2022-27664"},
		},
		{
			name:      "cpe disabled, override off",
			cfg:       MatcherConfig{UseCPEs: false, AlwaysUseCPEForStdlib: false},
			pkg:       stdlib("stdlib"),
			expectHit: false,
		},
		{
			name:      "package named go (not stdlib) with override on - cpe disabled (override only applies to stdlib)",
			cfg:       MatcherConfig{UseCPEs: false, AlwaysUseCPEForStdlib: true},
			pkg:       stdlib("go"),
			expectHit: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbtest.DBs(t, "istio-and-stdlib").
				SelectOnly("CVE-2022-27664").
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewGolangMatcher(c.cfg)
					findings := db.Match(t, matcher, c.pkg)
					if c.expectHit {
						findings.SelectMatch(c.expectCVEs[0]).
							SelectDetailByType(match.CPEMatch).
							AsCPESearch()
					} else {
						findings.IsEmpty()
					}
				})
		})
	}
}

// TestMatcher_ImportPathGranularityAdvisories covers the case where a Go advisory is filed
// against an import path inside a larger module (e.g. "golang.org/x/crypto/ssh") while the
// SBOM only carries the module path ("golang.org/x/crypto"). The matcher should surface
// such advisories via a path-segment-bounded prefix search on the module name, while
// avoiding false positives where another module shares only a name prefix substring.
func TestMatcher_ImportPathGranularityAdvisories(t *testing.T) {
	// vulnerable version range covers both packages so version isn't the limiting factor.
	cryptoSSHVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-import-path-1",
			Namespace: "github:language:go",
		},
		PackageName: "golang.org/x/crypto/ssh",
		Constraint:  version.MustGetConstraint("< 0.99.0", version.GolangFormat),
	}
	otelBaggageVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-mh2q-q3fh-2475",
			Namespace: "github:language:go",
		},
		PackageName: "go.opentelemetry.io/otel/baggage",
		Constraint:  version.MustGetConstraint("< 1.40.1", version.GolangFormat),
	}
	otelPropagationVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-mh2q-q3fh-2475",
			Namespace: "github:language:go",
		},
		PackageName: "go.opentelemetry.io/otel/propagation",
		Constraint:  version.MustGetConstraint("< 1.40.1", version.GolangFormat),
	}
	// boundary trap: a sibling module whose name shares only the "golang.org/x/crypto"
	// substring without a "/" segment break. The fix must not surface this advisory for
	// SBOM packages named "golang.org/x/crypto".
	cryptographerVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-boundary-trap",
			Namespace: "github:language:go",
		},
		PackageName: "golang.org/x/cryptographer",
		Constraint:  version.MustGetConstraint("< 99.0.0", version.GolangFormat),
	}
	// exact-match advisory against the parent module itself, used to confirm the
	// supplemental prefix search does not regress the existing exact-name path.
	parentExactVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "GHSA-parent-exact",
			Namespace: "github:language:go",
		},
		PackageName: "golang.org/x/crypto",
		Constraint:  version.MustGetConstraint("< 99.0.0", version.GolangFormat),
	}

	store := mock.VulnerabilityProvider(
		cryptoSSHVuln,
		otelBaggageVuln,
		otelPropagationVuln,
		cryptographerVuln,
		parentExactVuln,
	)

	cases := []struct {
		name        string
		pkg         pkg.Package
		expectedIDs []string
	}{
		{
			name: "module sbom surfaces import-path advisory under it",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "golang.org/x/crypto",
				Version:  "v0.10.0",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			// expects the import-path advisory AND the parent-exact advisory; the
			// boundary-trap advisory ("golang.org/x/cryptographer") must not surface.
			expectedIDs: []string{"GHSA-import-path-1", "GHSA-parent-exact"},
		},
		{
			name: "otel module sbom surfaces sibling import-path advisories filed under it",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "go.opentelemetry.io/otel",
				Version:  "v1.40.0",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			// both baggage and propagation advisories share the same GHSA ID; we
			// expect to see the GHSA at least once.
			expectedIDs: []string{"GHSA-mh2q-q3fh-2475"},
		},
		{
			name: "exact import-path sbom still matches exact advisory (no regression)",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "golang.org/x/crypto/ssh",
				Version:  "v0.10.0",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			expectedIDs: []string{"GHSA-import-path-1"},
		},
		{
			name: "single-segment package name does not fan out to corpus",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "stdlib",
				Version:  "v0.10.0",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			expectedIDs: nil,
		},
		{
			name: "non-go package type is not affected by prefix search",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "golang.org/x/crypto",
				Version:  "v0.10.0",
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
			},
			expectedIDs: nil,
		},
	}

	matcher := NewGolangMatcher(MatcherConfig{})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			actual, _, err := matcher.Match(store, c.pkg)
			require.NoError(t, err)

			var gotIDs []string
			for _, m := range actual {
				if !slices.Contains(gotIDs, m.Vulnerability.ID) {
					gotIDs = append(gotIDs, m.Vulnerability.ID)
				}
			}
			sort.Strings(gotIDs)

			expected := append([]string(nil), c.expectedIDs...)
			sort.Strings(expected)

			assert.Equal(t, expected, gotIDs, "unexpected vulnerability matches for package %q", c.pkg.Name)

			// double-check the boundary trap never surfaces, regardless of the
			// per-case expectation.
			for _, m := range actual {
				assert.NotEqual(t, "GHSA-boundary-trap", m.Vulnerability.ID,
					"boundary-trap advisory for %q must not match SBOM package %q",
					m.Vulnerability.PackageName, c.pkg.Name)
			}
		})
	}

	// verify the helper directly so the path-segment boundary is locked down.
	assert.True(t, strings.HasPrefix("golang.org/x/crypto/ssh", "golang.org/x/crypto/"))
	assert.False(t, strings.HasPrefix("golang.org/x/cryptographer", "golang.org/x/crypto/"))
}
