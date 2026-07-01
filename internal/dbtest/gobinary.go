package dbtest

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft"
	syftGolang "github.com/anchore/syft/syft/pkg/cataloger/golang"
)

// GoBinaryFixture builds the Go binary fixture in the calling package's
// testdata/<fixtureName> directory and scans the resulting binary through
// grype's production package provider with Go function-symbol capture enabled —
// the same path `grype ./some-binary` takes. This yields packages carrying the
// exact symbols grype sees in the field, so matcher tests can exercise the
// gosymbols qualifier against real artifact data rather than hand-written symbol
// lists.
//
// The fixture directory must contain a Makefile whose default target builds the
// program to ./binary; make rebuilds only when sources change. Building may fetch
// pinned, checksummed modules for fixtures that depend on them.
func GoBinaryFixture(t testing.TB, fixtureName string) *GoBinary {
	t.Helper()

	_, callerFile, _, ok := runtime.Caller(1)
	require.True(t, ok, "failed to get caller information")
	fixtureDir := filepath.Join(filepath.Dir(callerFile), "testdata", fixtureName)

	buildGoBinaryFixture(t, fixtureDir)

	binPath := filepath.Join(fixtureDir, "binary")

	// mirror grype's getProviderConfig: capture Go binary function symbols so the
	// gosymbols qualifier has the per-symbol evidence it needs.
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.Packages.Golang = cfg.Packages.Golang.WithCaptureSymbols(syftGolang.SymbolScopeAll)

	pkgs, _, _, err := pkg.Provide(binPath, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{SBOMOptions: cfg},
	})
	require.NoErrorf(t, err, "scanning go binary fixture %q", fixtureName)

	return &GoBinary{t: t, name: fixtureName, pkgs: pkgs}
}

// buildGoBinaryFixture runs `make` in the fixture directory so the compiled
// binary is present and up to date before scanning.
func buildGoBinaryFixture(t testing.TB, fixtureDir string) {
	t.Helper()
	cmd := exec.Command("make")
	cmd.Dir = fixtureDir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "building go binary fixture in %q:\n%s", fixtureDir, string(out))
}

// GoBinary holds the packages cataloged from a compiled Go binary fixture.
type GoBinary struct {
	t    testing.TB
	name string
	pkgs []pkg.Package
}

// Package returns a builder seeded from the cataloged module package with the
// given name (e.g. "stdlib" or "golang.org/x/net"), preserving its real
// metadata and symbols. Fails the test if no such package was cataloged. Use
// WithVersion to place the package inside a specific advisory's vulnerable range.
func (g *GoBinary) Package(name string) *PackageBuilder {
	g.t.Helper()
	var found []string
	for _, p := range g.pkgs {
		if p.Name == name {
			return newPackageBuilderFromPackage(p)
		}
		found = append(found, p.Name)
	}
	g.t.Fatalf("package %q not found in go binary fixture %q; cataloged packages: %v", name, g.name, found)
	return nil
}
