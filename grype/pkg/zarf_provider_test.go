package pkg

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestZarfPackage(t *testing.T, sbomFiles map[string]string) string {
	t.Helper()

	// build sboms.tar in memory
	var sbomBuf bytes.Buffer
	sbomTW := tar.NewWriter(&sbomBuf)
	for name, content := range sbomFiles {
		require.NoError(t, sbomTW.WriteHeader(&tar.Header{
			Name: name,
			Size: int64(len(content)),
			Mode: 0o600,
		}))
		_, err := sbomTW.Write([]byte(content))
		require.NoError(t, err)
	}
	require.NoError(t, sbomTW.Close())

	// build outer .tar.zst with sboms.tar entry
	outPath := filepath.Join(t.TempDir(), "test-package.tar.zst")
	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer f.Close()

	zw, err := zstd.NewWriter(f)
	require.NoError(t, err)

	tw := tar.NewWriter(zw)
	sbomBytes := sbomBuf.Bytes()
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "sboms.tar",
		Size: int64(len(sbomBytes)),
		Mode: 0o600,
	}))
	_, err = tw.Write(sbomBytes)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())

	return outPath
}

func TestZarfProvider(t *testing.T) {
	sbomContent, err := os.ReadFile("testdata/syft-multiple-ecosystems.json")
	require.NoError(t, err)

	tests := []struct {
		name      string
		userInput string
		sbomFiles map[string]string
		wantPkgs  bool
		wantErr   bool
	}{
		{
			name: "reads single SBOM from Zarf package",
			sbomFiles: map[string]string{
				"sbom-image.json": string(sbomContent),
			},
			wantPkgs: true,
		},
		{
			name: "reads multiple SBOMs from Zarf package",
			sbomFiles: map[string]string{
				"sbom-image-a.json": string(sbomContent),
				"sbom-image-b.json": string(sbomContent),
			},
			wantPkgs: true,
		},
		{
			name:      "non-zarf prefix returns errDoesNotProvide",
			userInput: "dir:/some/path",
			wantErr:   true,
		},
		{
			name:      "missing file returns error",
			userInput: "zarf:/nonexistent/file.tar.zst",
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userInput := tc.userInput
			if userInput == "" && tc.sbomFiles != nil {
				archivePath := createTestZarfPackage(t, tc.sbomFiles)
				userInput = "zarf:" + archivePath
			}

			applyChannel := getDistroChannelApplier(nil)
			packages, ctx, _, err := zarfProvider(userInput, ProviderConfig{}, applyChannel)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tc.wantPkgs {
				assert.NotEmpty(t, packages)
				assert.NotNil(t, ctx.Source)
				_, ok := ctx.Source.Metadata.(ZarfPackageMetadata)
				assert.True(t, ok, "expected ZarfPackageMetadata in context source")
			}
		})
	}
}

func TestZarfProvider_MultiSBOM_MergesPackages(t *testing.T) {
	sbomContent, err := os.ReadFile("testdata/syft-multiple-ecosystems.json")
	require.NoError(t, err)

	// single SBOM baseline
	singlePath := createTestZarfPackage(t, map[string]string{
		"sbom-a.json": string(sbomContent),
	})

	applyChannel := getDistroChannelApplier(nil)
	singlePkgs, _, _, err := zarfProvider("zarf:"+singlePath, ProviderConfig{}, applyChannel)
	require.NoError(t, err)

	// two copies of the same SBOM should yield roughly double the packages
	doublePath := createTestZarfPackage(t, map[string]string{
		"sbom-a.json": string(sbomContent),
		"sbom-b.json": string(sbomContent),
	})

	doublePkgs, _, _, err := zarfProvider("zarf:"+doublePath, ProviderConfig{}, applyChannel)
	require.NoError(t, err)

	assert.Greater(t, len(doublePkgs), len(singlePkgs), "two SBOMs should produce more packages than one")
}

// TestZarfProvider_ProvenanceLocations verifies that every package returned from
// a Zarf scan carries a synthetic `zarf:` Location identifying which bundled
// SBOM it came from. The fixture has source.name=null, so the tar entry filename
// is used as the fallback identifier.
func TestZarfProvider_ProvenanceLocations(t *testing.T) {
	sbomContent, err := os.ReadFile("testdata/syft-multiple-ecosystems.json")
	require.NoError(t, err)

	archivePath := createTestZarfPackage(t, map[string]string{
		"sbom-image-a.json": string(sbomContent),
		"sbom-image-b.json": string(sbomContent),
	})

	applyChannel := getDistroChannelApplier(nil)
	packages, _, _, err := zarfProvider("zarf:"+archivePath, ProviderConfig{}, applyChannel)
	require.NoError(t, err)
	require.NotEmpty(t, packages)

	expected := map[string]bool{
		"zarf:sbom-image-a.json": false,
		"zarf:sbom-image-b.json": false,
	}

	for _, pkg := range packages {
		var foundZarfLoc bool
		for _, loc := range pkg.Locations.ToSlice() {
			if !strings.HasPrefix(loc.RealPath, zarfLocationPrefix) {
				continue
			}
			foundZarfLoc = true
			if _, ok := expected[loc.RealPath]; ok {
				expected[loc.RealPath] = true
			}
		}
		assert.True(t, foundZarfLoc, "package %q missing a zarf: provenance location (locations=%v)", pkg.Name, pkg.Locations.ToSlice())
	}

	for ident, seen := range expected {
		assert.True(t, seen, "expected to see at least one package annotated with %q", ident)
	}
}

// TestZarfProvider_PreservesPerSBOMDistro verifies that when a Zarf bundle
// contains SBOMs from different distros, each package retains its own distro
// context. This is the core correctness property the design hinges on.
func TestZarfProvider_PreservesPerSBOMDistro(t *testing.T) {
	alpineSBOM, err := os.ReadFile("testdata/syft-multiple-ecosystems.json") // alpine 3.12.0
	require.NoError(t, err)
	debianSBOM, err := os.ReadFile("testdata/syft-spring.json") // debian 9
	require.NoError(t, err)

	archivePath := createTestZarfPackage(t, map[string]string{
		"sbom-alpine.json": string(alpineSBOM),
		"sbom-debian.json": string(debianSBOM),
	})

	applyChannel := getDistroChannelApplier(nil)
	packages, _, _, err := zarfProvider("zarf:"+archivePath, ProviderConfig{}, applyChannel)
	require.NoError(t, err)
	require.NotEmpty(t, packages)

	distroCounts := map[string]int{}
	for _, pkg := range packages {
		if pkg.Distro == nil {
			distroCounts["<nil>"]++
			continue
		}
		distroCounts[string(pkg.Distro.Type)]++
	}

	assert.Greater(t, distroCounts["alpine"], 0, "expected at least one package with alpine distro, got %v", distroCounts)
	assert.Greater(t, distroCounts["debian"], 0, "expected at least one package with debian distro, got %v", distroCounts)
}

// TestZarfProvider_EmptySBOMYieldsNoFindings verifies that a Zarf package
// containing only SBOMs with zero artifacts (e.g. FROM-scratch images) returns
// an empty package list without erroring. Matches the behavior of the direct
// `sbom:` provider on the same input.
func TestZarfProvider_EmptySBOMYieldsNoFindings(t *testing.T) {
	sbomContent, err := os.ReadFile("testdata/syft-multiple-ecosystems.json")
	require.NoError(t, err)

	// zero out the artifacts array to simulate an SBOM produced from a
	// FROM-scratch image (no packages to catalog)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(sbomContent, &raw))
	raw["artifacts"] = []any{}
	emptied, err := json.Marshal(raw)
	require.NoError(t, err)

	archivePath := createTestZarfPackage(t, map[string]string{
		"empty-sbom.json": string(emptied),
	})

	applyChannel := getDistroChannelApplier(nil)
	packages, ctx, _, err := zarfProvider("zarf:"+archivePath, ProviderConfig{}, applyChannel)
	require.NoError(t, err)
	assert.Empty(t, packages, "expected no packages from a zero-artifact SBOM")
	assert.NotNil(t, ctx.Source, "expected source context to be populated even with empty packages")
}

// TestZarfProvider_AllEntriesInvalidReturnsError verifies that when no entries
// in sboms.tar can be parsed as SBOMs (e.g. only HTML reports), the provider
// returns an error so the user gets a signal that nothing was scanned.
func TestZarfProvider_AllEntriesInvalidReturnsError(t *testing.T) {
	archivePath := createTestZarfPackage(t, map[string]string{
		"compare.html":    "<html><body>not an sbom</body></html>",
		"not-an-sbom.txt": "random junk that isn't an SBOM",
	})

	applyChannel := getDistroChannelApplier(nil)
	_, _, _, err := zarfProvider("zarf:"+archivePath, ProviderConfig{}, applyChannel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SBOMs could be parsed")
}
