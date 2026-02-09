package dbtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestComputeInputHash(t *testing.T) {
	// create a temporary directory with some test files
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("content1"), 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "file2.txt"), []byte("content2"), 0644)
	require.NoError(t, err)

	// compute hash
	hash1, err := computeInputHash(tempDir)
	require.NoError(t, err)
	assert.NotEmpty(t, hash1)

	// same content should produce same hash
	hash2, err := computeInputHash(tempDir)
	require.NoError(t, err)
	assert.Equal(t, hash1, hash2)

	// modify a file
	err = os.WriteFile(filepath.Join(tempDir, "file1.txt"), []byte("modified"), 0644)
	require.NoError(t, err)

	// hash should be different
	hash3, err := computeInputHash(tempDir)
	require.NoError(t, err)
	assert.NotEqual(t, hash1, hash3)
}

func TestCacheValidation(t *testing.T) {
	cacheDir := t.TempDir()
	testHash := "abc123"

	// initially cache should not be valid
	assert.False(t, isCacheValid(cacheDir, testHash))

	// write hash
	err := writeStoredHash(cacheDir, testHash)
	require.NoError(t, err)

	// now cache should be valid
	assert.True(t, isCacheValid(cacheDir, testHash))

	// different hash should not be valid
	assert.False(t, isCacheValid(cacheDir, "different"))

	// invalidate cache
	err = invalidateCache(cacheDir)
	require.NoError(t, err)

	// cache directory should be removed
	_, err = os.Stat(cacheDir)
	assert.True(t, os.IsNotExist(err))
}

func TestPackageBuilder(t *testing.T) {
	p := NewPackage("test-pkg", "1.0.0", syftPkg.DebPkg).
		WithCPE("cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*").
		WithPURL("pkg:deb/debian/test-pkg@1.0.0").
		Build()

	assert.Equal(t, "test-pkg", p.Name)
	assert.Equal(t, "1.0.0", p.Version)
	assert.Equal(t, syftPkg.DebPkg, p.Type)
	assert.Len(t, p.CPEs, 1)
	assert.Equal(t, "pkg:deb/debian/test-pkg@1.0.0", p.PURL)
	assert.NotEmpty(t, p.ID)
}

func TestGenerateListingFile(t *testing.T) {
	// create test results directory
	resultsDir := filepath.Join(t.TempDir(), "results")
	err := os.MkdirAll(resultsDir, 0755)
	require.NoError(t, err)

	// create a test result file
	resultFile := filepath.Join(resultsDir, "CVE-2024-0001.json")
	err = os.WriteFile(resultFile, []byte(`{"test": "data"}`), 0644)
	require.NoError(t, err)

	// generate listing
	listingPath := filepath.Join(resultsDir, "listing.xxh64")
	err = generateListingFile(resultsDir, listingPath)
	require.NoError(t, err)

	// verify listing file exists
	_, err = os.Stat(listingPath)
	require.NoError(t, err)

	// read listing content
	content, err := os.ReadFile(listingPath)
	require.NoError(t, err)

	// should contain the result file path
	assert.Contains(t, string(content), "results/CVE-2024-0001.json")
}
