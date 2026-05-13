package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
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
