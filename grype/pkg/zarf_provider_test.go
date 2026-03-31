package pkg

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
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
