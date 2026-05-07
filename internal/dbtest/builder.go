package dbtest

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/OneOfOne/xxhash"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/provider"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/vulnerability"
)

// DefaultSchemaVersions controls which schema versions Build() generates by default.
// Currently only v6; v7 can be added here when ready.
var DefaultSchemaVersions = []int{v6.ModelVersion}

// selectionHashTruncateLen is the number of hex characters to use when creating
// subdirectory names from selection hashes (for readability).
const selectionHashTruncateLen = 12

// Builder provides a fluent API for building test databases from fixture directories.
type Builder struct {
	t           *testing.T
	fixtureName string
	fixtureDir  string
	cacheDir    string
	selections  []string // patterns to filter which vulnerability records are included
}

// DBs creates a new Builder for the named fixture.
// The fixture is expected to be in a "testdata" directory relative to the calling test file.
//
// Example:
//
//	for _, db := range dbtest.DBs(t, "my-fixture").Build() {
//	    t.Run(db.Name, func(t *testing.T) {
//	        // use db as vulnerability.Provider
//	    })
//	}
func DBs(t *testing.T, fixtureName string) *Builder {
	t.Helper()

	// find the testdata directory relative to the calling test file
	_, callerFile, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("failed to get caller information")
	}

	callerDir := filepath.Dir(callerFile)
	fixtureDir := filepath.Join(callerDir, "testdata", fixtureName)
	cacheDir := filepath.Join(callerDir, "testdata", "cache", "db", fixtureName)

	return &Builder{
		t:           t,
		fixtureName: fixtureName,
		fixtureDir:  fixtureDir,
		cacheDir:    cacheDir,
	}
}

// SharedDBs creates a Builder for a fixture in the shared fixture directory.
// Shared fixtures live in internal/dbtest/testdata/shared/{fixtureName} and can be
// used by tests in any package, enabling cross-package fixture sharing.
//
// Example:
//
//	// from any test file in any package:
//	dbtest.SharedDBs(t, "common-debian").Run(func(t *testing.T, db *dbtest.DB) {
//	    // use the shared fixture
//	})
func SharedDBs(t *testing.T, fixtureName string) *Builder {
	t.Helper()

	// locate the dbtest package directory (where this source file lives)
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get dbtest package location")
	}
	dbtestDir := filepath.Dir(thisFile)

	fixtureDir := filepath.Join(dbtestDir, "testdata", "shared", fixtureName)
	cacheDir := filepath.Join(dbtestDir, "testdata", "cache", "db", "shared", fixtureName)

	return &Builder{
		t:           t,
		fixtureName: fixtureName,
		fixtureDir:  fixtureDir,
		cacheDir:    cacheDir,
	}
}

// SelectOnly specifies patterns to filter which vulnerability records are included in the built database.
// This enables creating focused test databases from larger fixtures.
//
// Pattern types:
//   - CVE ID only: "CVE-2024-1234" (matches any namespace containing this CVE)
//   - Namespace only: "debian:10" (matches all CVEs in that namespace)
//   - Full identifier: "debian:10/CVE-2024-1234" (exact match)
//
// Multiple patterns are combined with OR logic (union).
// If no selections are specified, all records are included.
//
// Example:
//
//	// select specific CVEs across all namespaces
//	dbtest.SharedDBs(t, "large-fixture").SelectOnly("CVE-2024-1234", "CVE-2024-5678").Build()
//
//	// select all CVEs in a namespace
//	dbtest.DBs(t, "fixture").SelectOnly("debian:10").Build()
//
//	// combine namespace and CVE selections
//	dbtest.SharedDBs(t, "fixture").SelectOnly("debian:10", "CVE-2024-9999").Build()
func (b *Builder) SelectOnly(patterns ...string) *Builder {
	b.selections = append(b.selections, patterns...)
	return b
}

// Run executes a test function for each database built from the fixture.
// This is a convenience method that wraps Build() with the common
// for-loop and t.Run pattern.
func (b *Builder) Run(fn func(t *testing.T, db *DB)) {
	b.t.Helper()
	for _, db := range b.Build() {
		b.t.Run(db.Name, func(t *testing.T) {
			fn(t, db)
		})
	}
}

// Build builds databases for the specified schema versions (or DefaultSchemaVersions if none specified).
// Returns a slice of DB pointers that implement vulnerability.Provider.
func (b *Builder) Build(schemas ...int) []*DB {
	b.t.Helper()

	if len(schemas) == 0 {
		schemas = DefaultSchemaVersions
	}

	inputHash, cacheDir := b.prepareCache()
	states := b.loadStates()

	var dbs []*DB
	for _, schema := range schemas {
		dbs = append(dbs, b.buildSchema(schema, states, inputHash, cacheDir))
	}

	b.t.Cleanup(func() {
		for _, d := range dbs {
			if err := d.Close(); err != nil {
				b.t.Errorf("failed to close database %s: %v", d.Name, err)
			}
		}
	})

	return dbs
}

// prepareCache validates and prepares the cache directory, returning the input hash and cache path.
func (b *Builder) prepareCache() (inputHash string, cacheDir string) {
	b.t.Helper()

	if _, err := os.Stat(b.fixtureDir); os.IsNotExist(err) {
		b.t.Fatalf("fixture directory does not exist: %s", b.fixtureDir)
	}

	hash, err := b.computeInputHash()
	if err != nil {
		b.t.Fatalf("failed to compute input hash: %v", err)
	}

	cacheDir = b.effectiveCacheDir()

	if !isCacheValid(cacheDir, hash) {
		if err := invalidateCache(cacheDir); err != nil {
			b.t.Fatalf("failed to invalidate cache: %v", err)
		}
	}

	if err := ensureCacheDir(cacheDir); err != nil {
		b.t.Fatalf("failed to create cache directory: %v", err)
	}

	return hash, cacheDir
}

// loadStates parses provider states from the fixture, applying selections if specified.
func (b *Builder) loadStates() provider.States {
	b.t.Helper()

	states, err := parseWorkspaceProviders(b.fixtureDir)
	if err != nil {
		b.t.Fatalf("failed to parse fixture providers: %v", err)
	}
	if len(states) == 0 {
		b.t.Fatalf("no providers found in fixture: %s", b.fixtureDir)
	}

	if len(b.selections) == 0 {
		return states
	}

	// create filtered workspace and re-parse
	workingDir := b.createFilteredWorkspace(states)
	states, err = parseWorkspaceProviders(workingDir)
	if err != nil {
		b.t.Fatalf("failed to parse filtered workspace: %v", err)
	}
	if len(states) == 0 {
		b.t.Fatalf("no matching records found for selections: %v", b.selections)
	}

	return states
}

// computeInputHash computes a hash of the fixture directory contents plus any selections.
// When selections are present, only the matching files are hashed to avoid unnecessary
// cache invalidation when unrelated files change.
func (b *Builder) computeInputHash() (string, error) {
	return computeFixtureHash(b.fixtureDir, b.selections)
}

// effectiveCacheDir returns the cache directory to use, accounting for selections.
func (b *Builder) effectiveCacheDir() string {
	if len(b.selections) == 0 {
		return b.cacheDir
	}
	selHash := hashSelections(b.selections)[:selectionHashTruncateLen]
	return filepath.Join(b.cacheDir, "selected", selHash)
}

// hashSelections returns a deterministic hash of the given selection patterns.
func hashSelections(selections []string) string {
	hasher := xxhash.New64()
	sorted := make([]string, len(selections))
	copy(sorted, selections)
	sort.Strings(sorted)
	for _, sel := range sorted {
		_, _ = hasher.Write([]byte(sel))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// computeFixtureHash computes a hash of fixture files, optionally filtered by selections.
func computeFixtureHash(fixtureDir string, selections []string) (string, error) {
	hasher := xxhash.New64()

	// include selections in hash for differentiation
	if len(selections) > 0 {
		_, _ = hasher.Write([]byte(hashSelections(selections)))
	}

	states, err := parseWorkspaceProviders(fixtureDir)
	if err != nil {
		return "", err
	}

	// sort providers for determinism
	sort.Slice(states, func(i, j int) bool {
		return states[i].Provider < states[j].Provider
	})

	for _, state := range states {
		// get result paths, filter if selections specified
		resultPaths := state.ResultPaths()
		if len(selections) > 0 {
			resultPaths = filterResultFiles(resultPaths, selections)
		}
		sort.Strings(resultPaths)

		// hash each result file
		for _, path := range resultPaths {
			relPath, err := filepath.Rel(fixtureDir, path)
			if err != nil {
				return "", err
			}
			if err := hashFile(hasher, fixtureDir, relPath); err != nil {
				return "", err
			}
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// createFilteredWorkspace creates a temporary workspace containing only records matching the selections.
func (b *Builder) createFilteredWorkspace(states provider.States) string {
	b.t.Helper()
	dir, err := copyFilteredWorkspace(b.t.TempDir(), states, b.selections)
	if err != nil {
		b.t.Fatalf("failed to create filtered workspace: %v", err)
	}
	return dir
}

// relativeResultPath returns the path of a fixture result file relative to its
// provider's "results/" directory (e.g. "rhel@9/cve-2024-0340.json"). If the
// "results/" segment is not present in the path, only the basename is returned
// to fall back to the prior behavior.
func relativeResultPath(path string) string {
	const sep = string(filepath.Separator) + "results" + string(filepath.Separator)
	idx := strings.LastIndex(path, sep)
	if idx < 0 {
		return filepath.Base(path)
	}
	return path[idx+len(sep):]
}

// copyFilteredWorkspace copies matching records from states into outputDir.
func copyFilteredWorkspace(outputDir string, states provider.States, selections []string) (string, error) {
	for _, state := range states {
		matchedPaths := filterResultFiles(state.ResultPaths(), selections)
		if len(matchedPaths) == 0 {
			continue
		}

		writer := provider.NewWorkspaceWriter(outputDir, state.Provider)

		var files []provider.File
		for _, path := range matchedPaths {
			// preserve relative subdirectory structure under "results/" (e.g.
			// "rhel@9.4+eus/cve-2024-0340.json") so namespace-prefixed result
			// files don't collide on filepath.Base() and overwrite each other.
			relPath := relativeResultPath(path)
			content, err := os.ReadFile(path) //nolint:gosec // path comes from filterResultFiles over the fixture's own results
			if err != nil {
				return "", fmt.Errorf("read result %q: %w", path, err)
			}
			file, err := writer.WriteResult(relPath, content)
			if err != nil {
				return "", fmt.Errorf("copy result %q: %w", path, err)
			}
			files = append(files, *file)
		}

		if err := writer.WriteListing(files); err != nil {
			return "", fmt.Errorf("write listing for %s: %w", state.Provider, err)
		}

		// compute listing file with digest
		listingPath := filepath.Join(outputDir, state.Provider, "results", "listing.xxh64")
		listingFile, err := provider.NewFile(listingPath)
		if err != nil {
			return "", fmt.Errorf("hash listing for %s: %w", state.Provider, err)
		}
		listingFile.Path = "results/listing.xxh64" // relative path for metadata

		newState := state
		newState.Listing = listingFile

		if err := writer.WriteState(newState); err != nil {
			return "", fmt.Errorf("write state for %s: %w", state.Provider, err)
		}
	}

	return outputDir, nil
}

// buildSchema builds a database for a specific schema version.
func (b *Builder) buildSchema(schema int, states provider.States, inputHash string, cacheDir string) *DB {
	b.t.Helper()

	schemaDir := filepath.Join(cacheDir, fmt.Sprintf("v%d", schema))
	dbPath := filepath.Join(schemaDir, v6.VulnerabilityDBFileName)

	// build if not cached
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if err := buildDatabase(schema, schemaDir, states); err != nil {
			b.t.Fatalf("failed to build v%d database: %v", schema, err)
		}
		if err := writeStoredHash(cacheDir, inputHash); err != nil {
			b.t.Fatalf("failed to write input hash: %v", err)
		}
	}

	vp, closer, err := openDatabase(schema, schemaDir)
	if err != nil {
		b.t.Fatalf("failed to open v%d database: %v", schema, err)
	}

	return &DB{
		Name:          fmt.Sprintf("v%d", schema),
		SchemaVersion: schema,
		Path:          schemaDir,
		provider:      vp,
		closer:        closer,
	}
}

// buildDatabase builds a vulnerability database for the given schema version.
func buildDatabase(schema int, outputDir string, states provider.States) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	cfg := db.BuildConfig{
		SchemaVersion:       schema,
		Directory:           outputDir,
		States:              states,
		Timestamp:           time.Now(),
		Hydrate:             true,
		IncludeCPEParts:     []string{"a", "h", "o"},
		InferNVDFixVersions: true, // match grype-db's production default so NVD fix metadata reaches matchers
	}

	return db.Build(cfg)
}

// openDatabase opens a vulnerability database and returns a provider.
func openDatabase(schema int, dbDir string) (vulnerability.Provider, io.Closer, error) {
	switch schema {
	case v6.ModelVersion:
		reader, err := v6.NewReader(v6.Config{DBDirPath: dbDir})
		if err != nil {
			return nil, nil, fmt.Errorf("open v6 database: %w", err)
		}
		return v6.NewVulnerabilityProvider(reader), reader, nil
	default:
		return nil, nil, fmt.Errorf("unsupported schema version: %d", schema)
	}
}
