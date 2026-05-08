package dbtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/anchore/grype/grype/db/provider/entry"
)

// testResults is the SQLite model for test database creation
type testResults struct {
	ID     string `gorm:"column:id;primaryKey"`
	Record []byte `gorm:"column:record"`
}

func (testResults) TableName() string {
	return "results"
}

func TestQueryRecords(t *testing.T) {
	// create a temp SQLite database with test records
	dbPath := filepath.Join(t.TempDir(), "results.db")
	db := createTestDB(t, dbPath)

	// insert test records
	records := []testResults{
		{ID: "debian:10/CVE-2024-1234", Record: []byte(`{"identifier": "debian:10/CVE-2024-1234"}`)},
		{ID: "debian:10/CVE-2024-5678", Record: []byte(`{"identifier": "debian:10/CVE-2024-5678"}`)},
		{ID: "debian:11/CVE-2024-1234", Record: []byte(`{"identifier": "debian:11/CVE-2024-1234"}`)},
		{ID: "ubuntu:20.04/CVE-2024-9999", Record: []byte(`{"identifier": "ubuntu:20.04/CVE-2024-9999"}`)},
		{ID: "rhel:8/RHSA-2024:0001", Record: []byte(`{"identifier": "rhel:8/RHSA-2024:0001"}`)},
	}
	for _, r := range records {
		require.NoError(t, db.Create(&r).Error)
	}

	tests := []struct {
		name     string
		patterns []string
		wantIDs  []string
	}{
		{
			name:     "no patterns returns all",
			patterns: nil,
			wantIDs:  []string{"debian:10/CVE-2024-1234", "debian:10/CVE-2024-5678", "debian:11/CVE-2024-1234", "ubuntu:20.04/CVE-2024-9999", "rhel:8/RHSA-2024:0001"},
		},
		{
			name:     "match by CVE ID",
			patterns: []string{"CVE-2024-1234"},
			wantIDs:  []string{"debian:10/CVE-2024-1234", "debian:11/CVE-2024-1234"},
		},
		{
			name:     "match by namespace",
			patterns: []string{"debian:10"},
			wantIDs:  []string{"debian:10/CVE-2024-1234", "debian:10/CVE-2024-5678"},
		},
		{
			name:     "match by partial namespace",
			patterns: []string{"debian"},
			wantIDs:  []string{"debian:10/CVE-2024-1234", "debian:10/CVE-2024-5678", "debian:11/CVE-2024-1234"},
		},
		{
			name:     "match by exact ID",
			patterns: []string{"debian:11/CVE-2024-1234"},
			wantIDs:  []string{"debian:11/CVE-2024-1234"},
		},
		{
			name:     "match RHSA pattern",
			patterns: []string{"RHSA-2024"},
			wantIDs:  []string{"rhel:8/RHSA-2024:0001"},
		},
		{
			name:     "multiple patterns (OR)",
			patterns: []string{"CVE-2024-5678", "RHSA-2024"},
			wantIDs:  []string{"debian:10/CVE-2024-5678", "rhel:8/RHSA-2024:0001"},
		},
		{
			name:     "no matches",
			patterns: []string{"nonexistent"},
			wantIDs:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := entry.QueryRecords(dbPath, tt.patterns)
			require.NoError(t, err)

			var gotIDs []string
			for _, r := range got {
				gotIDs = append(gotIDs, r.ID)
			}

			if d := cmp.Diff(tt.wantIDs, gotIDs); d != "" {
				t.Errorf("QueryRecords() mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestFixtureExtractor_WriteTo(t *testing.T) {
	// create a mock vunnel cache with SQLite store
	vunnelCache := t.TempDir()
	createMockVunnelCache(t, vunnelCache, "debian", []testResults{
		{ID: "debian:11/CVE-2024-1234", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-1234", "A test vulnerability")},
		{ID: "debian:11/CVE-2024-5678", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-5678", "Another vulnerability")},
	})

	// extract to a new fixture
	fixtureDir := t.TempDir()
	extractor := NewFixtureExtractor(vunnelCache)
	err := extractor.
		From("debian").
		Select("CVE-2024-1234").
		WriteTo(fixtureDir)
	require.NoError(t, err)

	// verify the fixture structure (nested path: debian@11/CVE-2024-1234.json)
	verifyFixtureStructure(t, fixtureDir, "debian", []string{"debian@11/CVE-2024-1234.json"})

	// verify the metadata.json has flat-file store
	metadataPath := filepath.Join(fixtureDir, "debian", "metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	var metadata map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &metadata))
	require.Equal(t, "flat-file", metadata["store"])
}

func TestFixtureExtractor_AppendTo(t *testing.T) {
	// create a mock vunnel cache with SQLite store
	vunnelCache := t.TempDir()
	createMockVunnelCache(t, vunnelCache, "debian", []testResults{
		{ID: "debian:11/CVE-2024-1234", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-1234", "CVE 1234")},
		{ID: "debian:11/CVE-2024-5678", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-5678", "CVE 5678")},
		{ID: "debian:11/CVE-2024-9999", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-9999", "CVE 9999")},
	})

	fixtureDir := t.TempDir()
	extractor := NewFixtureExtractor(vunnelCache)

	// first extraction
	err := extractor.
		From("debian").
		Select("CVE-2024-1234").
		WriteTo(fixtureDir)
	require.NoError(t, err)

	// append more records
	err = extractor.
		From("debian").
		Select("CVE-2024-5678").
		AppendTo(fixtureDir)
	require.NoError(t, err)

	// verify both records exist (nested paths)
	verifyFixtureStructure(t, fixtureDir, "debian", []string{
		"debian@11/CVE-2024-1234.json",
		"debian@11/CVE-2024-5678.json",
	})
}

func TestFixtureExtractor_MultiProvider(t *testing.T) {
	// create mock vunnel cache with multiple providers
	vunnelCache := t.TempDir()
	createMockVunnelCache(t, vunnelCache, "debian", []testResults{
		{ID: "debian:11/CVE-2024-1234", Record: createVunnelEnvelope(t, "debian:11/CVE-2024-1234", "Debian vuln")},
	})
	createMockVunnelCache(t, vunnelCache, "nvd", []testResults{
		{ID: "nvd/CVE-2024-1234", Record: createVunnelEnvelope(t, "nvd/CVE-2024-1234", "NVD vuln")},
	})

	fixtureDir := t.TempDir()
	extractor := NewFixtureExtractor(vunnelCache)

	// extract from multiple providers
	err := extractor.
		FromMultiple().
		Provider("debian", "CVE-2024-1234").
		Provider("nvd", "CVE-2024-1234").
		WriteTo(fixtureDir)
	require.NoError(t, err)

	// verify both provider directories exist (nested paths)
	verifyFixtureStructure(t, fixtureDir, "debian", []string{"debian@11/CVE-2024-1234.json"})
	verifyFixtureStructure(t, fixtureDir, "nvd", []string{"nvd/CVE-2024-1234.json"})
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"debian:10/CVE-2024-1234", "debian@10/CVE-2024-1234"},
		{"nvd/CVE-2024-5678", "nvd/CVE-2024-5678"},
		{"simple", "simple"},
		{"ubuntu:20.04/CVE-2024-9999", "ubuntu@20.04/CVE-2024-9999"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizePath(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

// helper functions

func createTestDB(t *testing.T, dbPath string) *gorm.DB {
	t.Helper()

	connStr := "file:" + dbPath + "?cache=shared"
	db, err := gorm.Open(sqlite.Open(connStr), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)

	// create table
	require.NoError(t, db.AutoMigrate(&testResults{}))

	return db
}

func createMockVunnelCache(t *testing.T, vunnelRoot, providerName string, records []testResults) {
	t.Helper()

	// create provider directory structure
	providerDir := filepath.Join(vunnelRoot, providerName)
	resultsDir := filepath.Join(providerDir, "results")
	require.NoError(t, os.MkdirAll(resultsDir, 0755))

	// create SQLite database
	dbPath := filepath.Join(resultsDir, "results.db")
	db := createTestDB(t, dbPath)

	// insert records
	for _, r := range records {
		require.NoError(t, db.Create(&r).Error)
	}

	// create metadata.json
	metadata := map[string]interface{}{
		"provider":  providerName,
		"version":   1,
		"processor": "vunnel",
		"schema": map[string]string{
			"version": "1.0.0",
			"url":     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"store":     "sqlite",
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(providerDir, "metadata.json"), metadataBytes, 0644))
}

func createVunnelEnvelope(t *testing.T, identifier, description string) []byte {
	t.Helper()

	envelope := map[string]interface{}{
		"schema":     "https://raw.githubusercontent.com/anchore/vunnel/main/schema/vulnerability/os/schema-1.0.0.json",
		"identifier": identifier,
		"item": map[string]interface{}{
			"Vulnerability": map[string]interface{}{
				"Name":        filepath.Base(identifier),
				"Description": description,
				"Severity":    "Medium",
			},
		},
	}

	data, err := json.Marshal(envelope)
	require.NoError(t, err)
	return data
}

func verifyFixtureStructure(t *testing.T, fixtureDir, providerName string, expectedFiles []string) {
	t.Helper()

	// verify provider directory exists
	providerDir := filepath.Join(fixtureDir, providerName)
	_, err := os.Stat(providerDir)
	require.NoError(t, err, "provider directory should exist")

	// verify metadata.json exists
	_, err = os.Stat(filepath.Join(providerDir, "metadata.json"))
	require.NoError(t, err, "metadata.json should exist")

	// verify results directory exists
	resultsDir := filepath.Join(providerDir, "results")
	_, err = os.Stat(resultsDir)
	require.NoError(t, err, "results directory should exist")

	// verify listing file exists
	_, err = os.Stat(filepath.Join(resultsDir, "listing.xxh64"))
	require.NoError(t, err, "listing.xxh64 should exist")

	// verify expected result files exist
	for _, filename := range expectedFiles {
		path := filepath.Join(resultsDir, filename)
		_, err = os.Stat(path)
		require.NoError(t, err, "expected file %s should exist", filename)
	}
}
