package dbtest

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

	// verify fixture directory exists
	if _, err := os.Stat(b.fixtureDir); os.IsNotExist(err) {
		b.t.Fatalf("fixture directory does not exist: %s", b.fixtureDir)
	}

	// compute input hash for cache validation (includes selections if any)
	inputHash, err := b.computeInputHash()
	if err != nil {
		b.t.Fatalf("failed to compute input hash: %v", err)
	}

	// determine effective cache directory (may differ if selections are used)
	effectiveCacheDir := b.effectiveCacheDir()

	// check if cache is valid
	if !isCacheValid(effectiveCacheDir, inputHash) {
		// invalidate and rebuild
		if err := invalidateCache(effectiveCacheDir); err != nil {
			b.t.Fatalf("failed to invalidate cache: %v", err)
		}
	}

	// ensure cache directory exists
	if err := ensureCacheDir(effectiveCacheDir); err != nil {
		b.t.Fatalf("failed to create cache directory: %v", err)
	}

	// parse fixture providers
	states, err := parseWorkspaceProviders(b.fixtureDir)
	if err != nil {
		b.t.Fatalf("failed to parse fixture providers: %v", err)
	}

	if len(states) == 0 {
		b.t.Fatalf("no providers found in fixture: %s", b.fixtureDir)
	}

	// if selections are specified, create a filtered workspace
	if len(b.selections) > 0 {
		workingDir := b.createFilteredWorkspace(states)
		// re-parse from filtered workspace
		states, err = parseWorkspaceProviders(workingDir)
		if err != nil {
			b.t.Fatalf("failed to parse filtered workspace: %v", err)
		}
		if len(states) == 0 {
			b.t.Fatalf("no matching records found for selections: %v", b.selections)
		}
	}

	// build databases for each schema version
	var dbs []*DB
	for _, schema := range schemas {
		db := b.buildSchema(schema, states, inputHash, effectiveCacheDir)
		dbs = append(dbs, db)
	}

	// register cleanup to close all databases
	b.t.Cleanup(func() {
		for _, db := range dbs {
			if err := db.Close(); err != nil {
				b.t.Errorf("failed to close database %s: %v", db.Name, err)
			}
		}
	})

	return dbs
}

// computeInputHash computes a hash of the fixture directory contents plus any selections.
// When selections are present, only the matching files are hashed to avoid unnecessary
// cache invalidation when unrelated files change.
func (b *Builder) computeInputHash() (string, error) {
	hasher := xxhash.New64()

	// hash sorted selection strings for differentiation (empty loop if no selections)
	sorted := make([]string, len(b.selections))
	copy(sorted, b.selections)
	sort.Strings(sorted)
	for _, sel := range sorted {
		_, _ = hasher.Write([]byte(sel))
	}

	// find all provider directories and their metadata
	states, err := parseWorkspaceProviders(b.fixtureDir)
	if err != nil {
		return "", err
	}

	// sort providers by name for deterministic hashing
	sort.Slice(states, func(i, j int) bool {
		return states[i].Provider < states[j].Provider
	})

	// for each provider, hash metadata + result files (filtered if selections specified)
	for _, state := range states {
		// hash metadata.json path and content
		metadataRelPath := filepath.Join(state.Provider, "metadata.json")
		if err := hashFile(hasher, b.fixtureDir, metadataRelPath); err != nil {
			return "", err
		}

		// get result paths, filter if selections are specified
		allPaths := state.ResultPaths()
		var resultPaths []string
		if len(b.selections) > 0 {
			resultPaths = filterResultFiles(allPaths, b.selections)
		} else {
			resultPaths = allPaths
		}

		// sort for determinism
		sort.Strings(resultPaths)

		// hash each result file
		for _, path := range resultPaths {
			relPath, err := filepath.Rel(b.fixtureDir, path)
			if err != nil {
				return "", err
			}
			if err := hashFile(hasher, b.fixtureDir, relPath); err != nil {
				return "", err
			}
		}
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// effectiveCacheDir returns the cache directory to use, accounting for selections.
func (b *Builder) effectiveCacheDir() string {
	if len(b.selections) == 0 {
		return b.cacheDir
	}

	// compute a short hash of the selections for the subdirectory name
	hasher := xxhash.New64()
	sorted := make([]string, len(b.selections))
	copy(sorted, b.selections)
	sort.Strings(sorted)
	for _, sel := range sorted {
		_, _ = hasher.Write([]byte(sel))
	}
	selHash := hex.EncodeToString(hasher.Sum(nil))[:selectionHashTruncateLen]

	return filepath.Join(b.cacheDir, "selected", selHash)
}

// createFilteredWorkspace creates a temporary workspace containing only records matching the selections.
func (b *Builder) createFilteredWorkspace(states provider.States) string {
	b.t.Helper()

	tmpDir := b.t.TempDir()

	for _, state := range states {
		// get all result paths from the original state
		allPaths := state.ResultPaths()

		// filter to only matching records
		matchedPaths := filterResultFiles(allPaths, b.selections)

		if len(matchedPaths) == 0 {
			continue // skip provider with no matching results
		}

		// create workspace writer for this provider
		writer := provider.NewWorkspaceWriter(tmpDir, state.Provider)

		// copy matched results
		var files []provider.File
		for _, path := range matchedPaths {
			file, err := writer.CopyResultFrom(path)
			if err != nil {
				b.t.Fatalf("failed to copy result %q: %v", path, err)
			}
			files = append(files, *file)
		}

		// write listing file
		if err := writer.WriteListing(files); err != nil {
			b.t.Fatalf("failed to write listing for provider %s: %v", state.Provider, err)
		}

		// create new state with updated listing reference
		newState := state
		newState.Listing = &provider.File{
			Path:      "results/listing.xxh64",
			Algorithm: "xxh64",
		}

		// write state
		if err := writer.WriteState(newState); err != nil {
			b.t.Fatalf("failed to write state for provider %s: %v", state.Provider, err)
		}
	}

	return tmpDir
}

// buildSchema builds a database for a specific schema version.
func (b *Builder) buildSchema(schema int, states provider.States, inputHash string, cacheDir string) *DB {
	b.t.Helper()

	schemaDir := filepath.Join(cacheDir, fmt.Sprintf("v%d", schema))
	dbPath := filepath.Join(schemaDir, v6.VulnerabilityDBFileName)

	// check if database already exists in cache
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// build the database
		if err := b.buildDatabase(schema, schemaDir, states); err != nil {
			b.t.Fatalf("failed to build v%d database: %v", schema, err)
		}

		// write input hash after successful build
		if err := writeStoredHash(cacheDir, inputHash); err != nil {
			b.t.Fatalf("failed to write input hash: %v", err)
		}
	}

	// open the database and create provider
	provider, closer, err := b.openDatabase(schema, schemaDir)
	if err != nil {
		b.t.Fatalf("failed to open v%d database: %v", schema, err)
	}

	return &DB{
		Name:          fmt.Sprintf("v%d", schema),
		SchemaVersion: schema,
		Path:          schemaDir,
		provider:      provider,
		closer:        closer,
	}
}

// buildDatabase builds a database using the db.Build function.
func (b *Builder) buildDatabase(schema int, outputDir string, states provider.States) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	cfg := db.BuildConfig{
		SchemaVersion:   schema,
		Directory:       outputDir,
		States:          states,
		Timestamp:       time.Now(),
		Hydrate:         true,
		IncludeCPEParts: []string{"a", "h", "o"}, // include application, hardware, and OS CPEs
	}

	if err := db.Build(cfg); err != nil {
		return fmt.Errorf("failed to build database: %w", err)
	}

	return nil
}

// openDatabase opens a database and returns a vulnerability provider.
func (b *Builder) openDatabase(schema int, dbDir string) (vulnerability.Provider, io.Closer, error) {
	switch schema {
	case v6.ModelVersion:
		reader, err := v6.NewReader(v6.Config{DBDirPath: dbDir})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to open v6 database: %w", err)
		}
		provider := v6.NewVulnerabilityProvider(reader)
		return provider, reader, nil
	default:
		return nil, nil, fmt.Errorf("unsupported schema version: %d", schema)
	}
}
