package dbtest

import (
	"encoding/hex"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"github.com/OneOfOne/xxhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests document the cache-invalidation contract for dbtest. CI restores
// **/testdata/cache via actions/cache with a restore-keys fallback; if our
// in-process cache key fails to invalidate when build behavior changes, a stale
// SQLite DB feeds the matcher and produces CI-only failures that reproduce
// nowhere else. The dimensions below are what we promise to invalidate on.

const (
	fakeSchemaTag = "v6.1.7"
	fakeBuildFP   = "deadbeef"
)

func mustWriteCSAFFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Minimal vunnel-style workspace: one provider directory with metadata.json
	// and a results subtree. Contents are arbitrary; only their digest matters.
	provider := filepath.Join(dir, "fakeprov")
	results := filepath.Join(provider, "results", "fakeprov")
	require.NoError(t, os.MkdirAll(results, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(provider, "metadata.json"), []byte(`{
  "provider": "fakeprov",
  "version": 1,
  "processor": "vunnel@test",
  "schema": {"version": "1.0.3", "url": "https://example.com/schema.json"},
  "urls": [],
  "timestamp": "2026-01-01T00:00:00Z",
  "listing": {
    "path": "results/listing.xxh64",
    "digest": "0000000000000000",
    "algorithm": "xxh64"
  },
  "stale": false
}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(results, "cve-1.json"), []byte(`{"id":"CVE-1","payload":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(results, "cve-2.json"), []byte(`{"id":"CVE-2","payload":1}`), 0o644))
	return dir
}

// TestCacheInvalidation_SchemaBumpInvalidates pins the promise that bumping
// any of v6.ModelVersion / Revision / Addition changes the cache key. A renamed
// JSON field on a blob is the canonical case: fixture content unchanged, cached
// DB now-stale.
func TestCacheInvalidation_SchemaBumpInvalidates(t *testing.T) {
	fixture := mustWriteCSAFFixture(t)

	before, err := computeFixtureHashWith(fixture, nil, "v6.1.6", fakeBuildFP)
	require.NoError(t, err)
	after, err := computeFixtureHashWith(fixture, nil, "v6.1.7", fakeBuildFP)
	require.NoError(t, err)

	assert.NotEqual(t, before, after, "schema version is part of the cache key; a bump must invalidate")
}

// TestCacheInvalidation_BuildSourceChangeInvalidates is the regression for the
// CI-only stale-DB failure that motivated this layer: a transformer bug fix
// without a schema bump. Fixture and schema unchanged, only the Go source that
// converts fixture→DB differs. The cache key must move.
func TestCacheInvalidation_BuildSourceChangeInvalidates(t *testing.T) {
	fixture := mustWriteCSAFFixture(t)

	before, err := computeFixtureHashWith(fixture, nil, fakeSchemaTag, "fingerprint-A")
	require.NoError(t, err)
	after, err := computeFixtureHashWith(fixture, nil, fakeSchemaTag, "fingerprint-B")
	require.NoError(t, err)

	assert.NotEqual(t, before, after, "build-source fingerprint is part of the cache key; a transformer fix must invalidate")
}

// TestCacheInvalidation_StableInputsStableKey is the inverse: if nothing the
// cache cares about changed, the key must be stable, otherwise we'd rebuild on
// every run and the cache buys nothing.
func TestCacheInvalidation_StableInputsStableKey(t *testing.T) {
	fixture := mustWriteCSAFFixture(t)

	first, err := computeFixtureHashWith(fixture, []string{"CVE-1"}, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)
	second, err := computeFixtureHashWith(fixture, []string{"CVE-1"}, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)

	assert.Equal(t, first, second, "identical inputs must produce identical keys")
}

// TestCacheInvalidation_FixtureContentInvalidates rounds out the contract:
// editing fixture content is what the original hash already covered, and that
// behavior must survive the refactor.
func TestCacheInvalidation_FixtureContentInvalidates(t *testing.T) {
	fixture := mustWriteCSAFFixture(t)
	target := filepath.Join(fixture, "fakeprov", "results", "fakeprov", "cve-1.json")

	before, err := computeFixtureHashWith(fixture, nil, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(target, []byte(`{"id":"CVE-1","payload":2}`), 0o644))

	after, err := computeFixtureHashWith(fixture, nil, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)
	assert.NotEqual(t, before, after, "fixture content is part of the cache key")
}

// TestCacheInvalidation_SelectionsAffectKey documents that distinct SelectOnly
// patterns produce distinct keys so the per-selection cache subdir stays
// addressable. Hash equality across selections would cause two tests to fight
// over one cache entry.
func TestCacheInvalidation_SelectionsAffectKey(t *testing.T) {
	fixture := mustWriteCSAFFixture(t)

	a, err := computeFixtureHashWith(fixture, []string{"CVE-1"}, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)
	b, err := computeFixtureHashWith(fixture, []string{"CVE-2"}, fakeSchemaTag, fakeBuildFP)
	require.NoError(t, err)

	assert.NotEqual(t, a, b, "different SelectOnly patterns must produce different keys")
}

// TestHashSourceTree_RespectsContractsAcrossFileKinds exercises the file-walk
// helper directly so the build fingerprint's behavior is testable without
// touching the real grype source tree.
func TestHashSourceTree_RespectsContractsAcrossFileKinds(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "pkg")
	require.NoError(t, os.MkdirAll(pkgDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "a.go"), []byte("package pkg\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "a_test.go"), []byte("package pkg\n"), 0o644))

	hashOnce := func() string {
		h := newTestHasher()
		require.NoError(t, hashSourceTree(h, root, "pkg"))
		return hex.EncodeToString(h.Sum(nil))
	}

	before := hashOnce()

	t.Run("non-test .go edits change the hash", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "a.go"), []byte("package pkg\nvar X = 1\n"), 0o644))
		assert.NotEqual(t, before, hashOnce())
		// revert so the rest of the subtests see the original baseline
		require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "a.go"), []byte("package pkg\n"), 0o644))
		assert.Equal(t, before, hashOnce())
	})

	t.Run("_test.go edits are ignored", func(t *testing.T) {
		require.NoError(t, os.WriteFile(filepath.Join(pkgDir, "a_test.go"), []byte("package pkg\nvar Y = 2\n"), 0o644))
		assert.Equal(t, before, hashOnce())
	})

	t.Run("testdata trees are skipped", func(t *testing.T) {
		testdataDir := filepath.Join(pkgDir, "testdata")
		require.NoError(t, os.MkdirAll(testdataDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(testdataDir, "fixture.go"), []byte("package fixture\n"), 0o644))
		assert.Equal(t, before, hashOnce())
	})
}

func newTestHasher() hash.Hash64 { return xxhash.New64() }
