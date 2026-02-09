package dbtest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/db/provider"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/vulnerability"
)

// DefaultSchemaVersions controls which schema versions Build() generates by default.
// Currently only v6; v7 can be added here when ready.
var DefaultSchemaVersions = []int{v6.ModelVersion}

// Builder provides a fluent API for building test databases from fixture directories.
type Builder struct {
	t           *testing.T
	fixtureName string
	fixtureDir  string
	cacheDir    string
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

	// compute input hash for cache validation
	inputHash, err := computeInputHash(b.fixtureDir)
	if err != nil {
		b.t.Fatalf("failed to compute input hash: %v", err)
	}

	// check if cache is valid
	if !isCacheValid(b.cacheDir, inputHash) {
		// invalidate and rebuild
		if err := invalidateCache(b.cacheDir); err != nil {
			b.t.Fatalf("failed to invalidate cache: %v", err)
		}
	}

	// ensure cache directory exists
	if err := ensureCacheDir(b.cacheDir); err != nil {
		b.t.Fatalf("failed to create cache directory: %v", err)
	}

	// parse fixture providers
	states, err := parseFixtureProviders(b.fixtureDir)
	if err != nil {
		b.t.Fatalf("failed to parse fixture providers: %v", err)
	}

	if len(states) == 0 {
		b.t.Fatalf("no providers found in fixture: %s", b.fixtureDir)
	}

	// build databases for each schema version
	var dbs []*DB
	for _, schema := range schemas {
		db := b.buildSchema(schema, states, inputHash)
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

// buildSchema builds a database for a specific schema version.
func (b *Builder) buildSchema(schema int, states provider.States, inputHash string) *DB {
	b.t.Helper()

	schemaDir := filepath.Join(b.cacheDir, fmt.Sprintf("v%d", schema))
	dbPath := filepath.Join(schemaDir, v6.VulnerabilityDBFileName)

	// check if database already exists in cache
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// build the database
		if err := b.buildDatabase(schema, schemaDir, states); err != nil {
			b.t.Fatalf("failed to build v%d database: %v", schema, err)
		}

		// write input hash after successful build
		if err := writeStoredHash(b.cacheDir, inputHash); err != nil {
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
		SchemaVersion: schema,
		Directory:     outputDir,
		States:        states,
		Timestamp:     time.Now(),
		Hydrate:       true,
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
