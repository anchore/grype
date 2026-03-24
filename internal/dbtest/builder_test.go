package dbtest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/provider"
	"github.com/anchore/grype/grype/pkg"
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

	// generate listing using provider package function
	listingPath := filepath.Join(resultsDir, "listing.xxh64")
	err = provider.GenerateListingFile(resultsDir, listingPath)
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

func TestSharedDBs(t *testing.T) {
	// test that SharedDBs can load fixtures from the shared directory
	SharedDBs(t, "all").Run(func(t *testing.T, db *DB) {
		assert.NotNil(t, db)
		assert.NotEmpty(t, db.Name)
		assert.NotEmpty(t, db.Path)

		// verify the provider works by calling a method that delegates to it
		names := db.PackageSearchNames(pkg.Package{Name: "openssl"})
		assert.NotNil(t, names)
	})
}

func TestSelectOnly(t *testing.T) {
	// test that SelectOnly filters results correctly
	// the all fixture has:
	//   - debian:11/CVE-2024-0727 (openssl)
	//   - nvd/CVE-2024-0727 (openssl CPE data)

	t.Run("select by CVE ID", func(t *testing.T) {
		SharedDBs(t, "all").SelectOnly("CVE-2024-0727").Run(func(t *testing.T, db *DB) {
			assert.NotNil(t, db)
		})
	})

	t.Run("select by namespace", func(t *testing.T) {
		SharedDBs(t, "all").SelectOnly("debian:11").Run(func(t *testing.T, db *DB) {
			assert.NotNil(t, db)
		})
	})

	t.Run("select exact identifier", func(t *testing.T) {
		SharedDBs(t, "all").SelectOnly("debian:11/CVE-2024-0727").Run(func(t *testing.T, db *DB) {
			assert.NotNil(t, db)
		})
	})
}

func TestSelectOnly_CacheIsolation(t *testing.T) {
	// verify that different selections use different cache directories
	// and that selection order doesn't matter

	t.Run("different selections use different cache dirs", func(t *testing.T) {
		builder1 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727")
		builder2 := SharedDBs(t, "all").SelectOnly("debian:11")

		dir1 := builder1.effectiveCacheDir()
		dir2 := builder2.effectiveCacheDir()

		assert.NotEqual(t, dir1, dir2, "different selections should use different cache directories")
		assert.Contains(t, dir1, "selected")
		assert.Contains(t, dir2, "selected")
	})

	t.Run("same selections in different order use same cache dir", func(t *testing.T) {
		builder1 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727", "debian:11")
		builder2 := SharedDBs(t, "all").SelectOnly("debian:11", "CVE-2024-0727")

		dir1 := builder1.effectiveCacheDir()
		dir2 := builder2.effectiveCacheDir()

		assert.Equal(t, dir1, dir2, "same selections in different order should use same cache directory")
	})

	t.Run("no selections uses base cache dir", func(t *testing.T) {
		builder := SharedDBs(t, "all")
		dir := builder.effectiveCacheDir()

		assert.NotContains(t, dir, "selected", "no selections should use base cache directory")
	})
}

func TestSelectOnly_InputHashIncludesFixtureAndSelections(t *testing.T) {
	// verify that the input hash changes when either fixture OR selections change

	t.Run("same fixture same selections produces same hash", func(t *testing.T) {
		builder1 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727")
		builder2 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727")

		hash1, err := builder1.computeInputHash()
		require.NoError(t, err)

		hash2, err := builder2.computeInputHash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "same fixture and selections should produce same hash")
	})

	t.Run("different selections produce different hash", func(t *testing.T) {
		builder1 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727")
		builder2 := SharedDBs(t, "all").SelectOnly("debian:11")

		hash1, err := builder1.computeInputHash()
		require.NoError(t, err)

		hash2, err := builder2.computeInputHash()
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2, "different selections should produce different hash")
	})

	t.Run("selection order does not affect hash", func(t *testing.T) {
		builder1 := SharedDBs(t, "all").SelectOnly("CVE-2024-0727", "debian:11")
		builder2 := SharedDBs(t, "all").SelectOnly("debian:11", "CVE-2024-0727")

		hash1, err := builder1.computeInputHash()
		require.NoError(t, err)

		hash2, err := builder2.computeInputHash()
		require.NoError(t, err)

		assert.Equal(t, hash1, hash2, "selection order should not affect hash")
	})
}

func TestCacheInvalidation_WithSelections(t *testing.T) {
	// test the full cache invalidation flow with selections
	// using a temporary fixture that we can modify

	// create a temporary fixture directory
	tempDir := t.TempDir()
	fixtureDir := filepath.Join(tempDir, "fixture")
	cacheDir := filepath.Join(tempDir, "cache")

	// create a minimal fixture structure
	providerDir := filepath.Join(fixtureDir, "test-provider")
	resultsDir := filepath.Join(providerDir, "results")
	require.NoError(t, os.MkdirAll(resultsDir, 0755))

	// write a result file
	resultContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-2024-0001","item":{}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-2024-0001.json"),
		[]byte(resultContent),
		0644,
	))

	// write metadata (must include listing reference)
	metadataContent := `{"provider":"test-provider","version":1,"processor":"test","schema":{"version":"1.0.0","url":"http://test"},"timestamp":"2024-01-01T00:00:00Z","store":"flat-file","listing":{"path":"results/listing.xxh64","algorithm":"xxh64"}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(providerDir, "metadata.json"),
		[]byte(metadataContent),
		0644,
	))

	// write listing file
	require.NoError(t, provider.GenerateListingFile(resultsDir, filepath.Join(resultsDir, "listing.xxh64")))

	// create a builder with custom paths
	builder := &Builder{
		t:           t,
		fixtureName: "test-fixture",
		fixtureDir:  fixtureDir,
		cacheDir:    cacheDir,
		selections:  []string{"CVE-2024-0001"},
	}

	// compute initial hash
	hash1, err := builder.computeInputHash()
	require.NoError(t, err)

	effectiveCache := builder.effectiveCacheDir()

	// simulate writing the hash (as if a build completed)
	require.NoError(t, ensureCacheDir(effectiveCache))
	require.NoError(t, writeStoredHash(effectiveCache, hash1))

	// cache should be valid
	assert.True(t, isCacheValid(effectiveCache, hash1), "cache should be valid with matching hash")

	// modify the fixture
	modifiedContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-2024-0001","item":{"modified":true}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-2024-0001.json"),
		[]byte(modifiedContent),
		0644,
	))

	// compute new hash
	hash2, err := builder.computeInputHash()
	require.NoError(t, err)

	// hashes should be different
	assert.NotEqual(t, hash1, hash2, "fixture modification should produce different hash")

	// cache should now be invalid
	assert.False(t, isCacheValid(effectiveCache, hash2), "cache should be invalid after fixture modification")

	// the effective cache dir should be the same (selections unchanged)
	assert.Equal(t, effectiveCache, builder.effectiveCacheDir(), "cache directory should not change when fixture changes")
}

func TestSelectOnly_HashOnlyIncludesSelectedFiles(t *testing.T) {
	// verify that adding unrelated files doesn't change the hash when using selections
	tempDir := t.TempDir()
	fixtureDir := filepath.Join(tempDir, "fixture")
	cacheDir := filepath.Join(tempDir, "cache")

	// create a fixture with multiple providers/CVEs
	providerDir := filepath.Join(fixtureDir, "test-provider")
	resultsDir := filepath.Join(providerDir, "results")
	require.NoError(t, os.MkdirAll(resultsDir, 0755))

	// write CVE-A (the one we'll select)
	cveAContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-A","item":{}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-A.json"),
		[]byte(cveAContent),
		0644,
	))

	// write CVE-B (unrelated)
	cveBContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-B","item":{}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-B.json"),
		[]byte(cveBContent),
		0644,
	))

	// write metadata (must include listing reference)
	metadataContent := `{"provider":"test-provider","version":1,"processor":"test","schema":{"version":"1.0.0","url":"http://test"},"timestamp":"2024-01-01T00:00:00Z","store":"flat-file","listing":{"path":"results/listing.xxh64","algorithm":"xxh64"}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(providerDir, "metadata.json"),
		[]byte(metadataContent),
		0644,
	))

	// write listing file
	require.NoError(t, provider.GenerateListingFile(resultsDir, filepath.Join(resultsDir, "listing.xxh64")))

	// create a builder that selects only CVE-A
	builder := &Builder{
		t:           t,
		fixtureName: "test-fixture",
		fixtureDir:  fixtureDir,
		cacheDir:    cacheDir,
		selections:  []string{"CVE-A"},
	}

	// compute initial hash
	hash1, err := builder.computeInputHash()
	require.NoError(t, err)

	// add an unrelated CVE-C file
	cveCContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-C","item":{}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-C.json"),
		[]byte(cveCContent),
		0644,
	))

	// regenerate listing file
	require.NoError(t, provider.GenerateListingFile(resultsDir, filepath.Join(resultsDir, "listing.xxh64")))

	// compute hash again
	hash2, err := builder.computeInputHash()
	require.NoError(t, err)

	// hash should NOT change because CVE-C is not selected
	assert.Equal(t, hash1, hash2, "adding unrelated file should not change hash when using selections")

	// verify that modifying the selected file DOES change the hash
	cveAModified := `{"schema":"1.0.0","identifier":"test:ns/CVE-A","item":{"modified":true}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-A.json"),
		[]byte(cveAModified),
		0644,
	))

	hash3, err := builder.computeInputHash()
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash3, "modifying selected file should change hash")
}

func TestSelectOnly_HashChangesWhenMetadataChanges(t *testing.T) {
	// verify that metadata changes DO affect the hash even with selections
	tempDir := t.TempDir()
	fixtureDir := filepath.Join(tempDir, "fixture")
	cacheDir := filepath.Join(tempDir, "cache")

	providerDir := filepath.Join(fixtureDir, "test-provider")
	resultsDir := filepath.Join(providerDir, "results")
	require.NoError(t, os.MkdirAll(resultsDir, 0755))

	// write a result file
	resultContent := `{"schema":"1.0.0","identifier":"test:ns/CVE-2024-0001","item":{}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(resultsDir, "CVE-2024-0001.json"),
		[]byte(resultContent),
		0644,
	))

	// write initial metadata (must include listing reference)
	metadataContent := `{"provider":"test-provider","version":1,"processor":"test","schema":{"version":"1.0.0","url":"http://test"},"timestamp":"2024-01-01T00:00:00Z","store":"flat-file","listing":{"path":"results/listing.xxh64","algorithm":"xxh64"}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(providerDir, "metadata.json"),
		[]byte(metadataContent),
		0644,
	))

	// write listing file
	require.NoError(t, provider.GenerateListingFile(resultsDir, filepath.Join(resultsDir, "listing.xxh64")))

	builder := &Builder{
		t:           t,
		fixtureName: "test-fixture",
		fixtureDir:  fixtureDir,
		cacheDir:    cacheDir,
		selections:  []string{"CVE-2024-0001"},
	}

	hash1, err := builder.computeInputHash()
	require.NoError(t, err)

	// modify metadata (e.g., version bump) - must keep listing reference
	modifiedMetadata := `{"provider":"test-provider","version":2,"processor":"test","schema":{"version":"1.0.0","url":"http://test"},"timestamp":"2024-01-01T00:00:00Z","store":"flat-file","listing":{"path":"results/listing.xxh64","algorithm":"xxh64"}}`
	require.NoError(t, os.WriteFile(
		filepath.Join(providerDir, "metadata.json"),
		[]byte(modifiedMetadata),
		0644,
	))

	hash2, err := builder.computeInputHash()
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2, "metadata changes should affect hash even with selections")
}
