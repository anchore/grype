package dbtest

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDiscoverFixtures(t *testing.T) {
	root := t.TempDir()

	// create several fixture directories
	fixture1 := filepath.Join(root, "fixtures", "fixture1")
	fixture2 := filepath.Join(root, "fixtures", "fixture2")
	fixture3 := filepath.Join(root, "other", "nested", "fixture3")
	nonFixture := filepath.Join(root, "not-a-fixture")

	for _, dir := range []string{fixture1, fixture2, fixture3, nonFixture} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}

	// add db.yaml to fixtures (but not to nonFixture)
	for _, dir := range []string{fixture1, fixture2, fixture3} {
		config := &FixtureConfig{AutoGenerate: true}
		require.NoError(t, config.Write(dir))
	}

	// discover from root
	fixtures, err := DiscoverFixtures(root)
	require.NoError(t, err)
	require.Len(t, fixtures, 3)
	require.Contains(t, fixtures, fixture1)
	require.Contains(t, fixtures, fixture2)
	require.Contains(t, fixtures, fixture3)
	require.NotContains(t, fixtures, nonFixture)
}

func TestDiscoverFixtures_MultipleRoots(t *testing.T) {
	root1 := t.TempDir()
	root2 := t.TempDir()

	fixture1 := filepath.Join(root1, "fixture1")
	fixture2 := filepath.Join(root2, "fixture2")

	require.NoError(t, os.MkdirAll(fixture1, 0755))
	require.NoError(t, os.MkdirAll(fixture2, 0755))

	config := &FixtureConfig{AutoGenerate: true}
	require.NoError(t, config.Write(fixture1))
	require.NoError(t, config.Write(fixture2))

	fixtures, err := DiscoverFixtures(root1, root2)
	require.NoError(t, err)
	require.Len(t, fixtures, 2)
	require.Contains(t, fixtures, fixture1)
	require.Contains(t, fixtures, fixture2)
}

func TestRegenerateFixture_NoConfig(t *testing.T) {
	dir := t.TempDir()

	result, err := RegenerateFixture(dir, RegenerateOptions{})
	require.NoError(t, err)
	require.True(t, result.Skipped)
	require.Equal(t, StatusNoConfig, result.Status)
	require.Contains(t, result.SkipReason, "no db.yaml")
}

func TestRegenerateFixture_Manual(t *testing.T) {
	dir := t.TempDir()

	config := &FixtureConfig{AutoGenerate: false}
	require.NoError(t, config.Write(dir))

	result, err := RegenerateFixture(dir, RegenerateOptions{})
	require.NoError(t, err)
	require.True(t, result.Skipped)
	require.Equal(t, StatusManual, result.Status)
	require.Contains(t, result.SkipReason, "manual")
}

func TestRegenerateFixture_ContentDrift_NoForce(t *testing.T) {
	dir := t.TempDir()

	config := &FixtureConfig{AutoGenerate: true}
	require.NoError(t, config.Write(dir))

	// create lock with wrong hash
	lock := &FixtureLock{
		ContentHash: "wrong",
		CreatedAt:   time.Now(),
		Providers:   map[string]ProviderState{},
	}
	require.NoError(t, lock.Write(dir))

	// add some content
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte("test"), 0644))

	result, err := RegenerateFixture(dir, RegenerateOptions{Force: false})
	require.NoError(t, err)
	require.True(t, result.Skipped)
	require.Equal(t, StatusContentDrift, result.Status)
	require.Contains(t, result.SkipReason, "lock hash")
}

func TestRegenerateFixture_DryRun(t *testing.T) {
	dir := t.TempDir()

	// create fixture content
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data.json"), []byte("original"), 0644))

	// compute hash and set up config/lock
	hash, err := ComputeFixtureContentHash(dir)
	require.NoError(t, err)

	config := &FixtureConfig{
		AutoGenerate: true,
		Extractions: map[string][]string{
			"debian": {"CVE-2024-1234"},
		},
	}
	require.NoError(t, config.Write(dir))

	lock := &FixtureLock{
		ContentHash: hash,
		CreatedAt:   time.Now(),
		Providers: map[string]ProviderState{
			"debian": {VunnelVersion: "vunnel@test", Timestamp: time.Now()},
		},
	}
	require.NoError(t, lock.Write(dir))

	// dry run should not modify anything
	result, err := RegenerateFixture(dir, RegenerateOptions{DryRun: true})
	require.NoError(t, err)
	require.False(t, result.Skipped)
	require.Equal(t, StatusOK, result.Status)

	// verify content is unchanged
	data, err := os.ReadFile(filepath.Join(dir, "data.json"))
	require.NoError(t, err)
	require.Equal(t, "original", string(data))
}

func TestRegenerateFixture_FullRegeneration(t *testing.T) {
	// create mock vunnel cache
	vunnelCache := t.TempDir()
	createMockVunnelCache(t, vunnelCache, "debian", []testResults{
		{ID: "debian:11/CVE-2024-1234", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-1234", "Test vulnerability")},
	})

	fixtureDir := t.TempDir()

	// create initial fixture using extractor
	extractor := NewFixtureExtractor(vunnelCache)
	err := extractor.From("debian").Select("CVE-2024-1234").WriteTo(fixtureDir)
	require.NoError(t, err)

	// verify db.yaml and db.lock were created
	_, err = os.Stat(filepath.Join(fixtureDir, ConfigFilename))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(fixtureDir, LockFilename))
	require.NoError(t, err)

	// read original lock
	originalLock, err := ReadLock(fixtureDir)
	require.NoError(t, err)
	originalHash := originalLock.ContentHash

	// regenerate the fixture
	result, err := RegenerateFixture(fixtureDir, RegenerateOptions{VunnelRoot: vunnelCache})
	require.NoError(t, err)
	require.False(t, result.Skipped)
	require.NoError(t, result.Error)

	// verify new lock was created
	newLock, err := ReadLock(fixtureDir)
	require.NoError(t, err)

	// content hash should be the same (same extraction)
	require.Equal(t, originalHash, newLock.ContentHash)

	// creation timestamp should be preserved
	require.Equal(t, originalLock.CreatedAt.Unix(), newLock.CreatedAt.Unix())

	// regenerated_at should be set
	require.NotNil(t, newLock.RegeneratedAt)
}

func TestDeleteFixtureContent(t *testing.T) {
	dir := t.TempDir()

	// create various files and directories
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "debian", "results"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "debian", "metadata.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "debian", "results", "CVE.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ConfigFilename), []byte("generated: true"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, LockFilename), []byte("{}"), 0644))

	// delete content
	err := deleteFixtureContent(dir)
	require.NoError(t, err)

	// verify db.yaml is preserved
	_, err = os.Stat(filepath.Join(dir, ConfigFilename))
	require.NoError(t, err)

	// verify everything else is deleted
	_, err = os.Stat(filepath.Join(dir, LockFilename))
	require.True(t, os.IsNotExist(err))

	_, err = os.Stat(filepath.Join(dir, "debian"))
	require.True(t, os.IsNotExist(err))
}

func TestRegenerateAll(t *testing.T) {
	root := t.TempDir()

	// create mock vunnel cache
	vunnelCache := t.TempDir()
	createMockVunnelCache(t, vunnelCache, "debian", []testResults{
		{ID: "debian:11/CVE-2024-1234", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-1234", "Test")},
	})

	// create multiple fixtures
	fixture1 := filepath.Join(root, "fixture1")
	fixture2 := filepath.Join(root, "fixture2")
	manualFixture := filepath.Join(root, "manual")

	// use extractor to create reproducible fixtures
	extractor := NewFixtureExtractor(vunnelCache)
	require.NoError(t, extractor.From("debian").Select("CVE-2024-1234").WriteTo(fixture1))
	require.NoError(t, extractor.From("debian").Select("CVE-2024-1234").WriteTo(fixture2))

	// create manual fixture
	require.NoError(t, os.MkdirAll(manualFixture, 0755))
	config := &FixtureConfig{AutoGenerate: false}
	require.NoError(t, config.Write(manualFixture))

	// regenerate all
	results, err := RegenerateAll([]string{root}, RegenerateOptions{VunnelRoot: vunnelCache})
	require.NoError(t, err)
	require.Len(t, results, 3)

	// count outcomes
	var regenerated, skipped int
	for _, r := range results {
		if r.Skipped {
			skipped++
		} else {
			regenerated++
		}
	}

	require.Equal(t, 2, regenerated) // fixture1 and fixture2
	require.Equal(t, 1, skipped)     // manual
}
