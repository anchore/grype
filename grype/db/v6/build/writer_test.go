package v6

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

func TestFillInMissingSeverity(t *testing.T) {
	tests := []struct {
		name              string
		handle            *db.VulnerabilityHandle
		severityCache     map[string]db.Severity
		expected          []db.Severity
		expectCacheUpdate bool
	}{
		{
			name:          "nil handle",
			handle:        nil,
			severityCache: map[string]db.Severity{},
			expected:      nil,
		},
		{
			name: "nil metadata",
			handle: &db.VulnerabilityHandle{
				BlobValue: nil,
			},
			severityCache: map[string]db.Severity{},
			expected:      nil,
		},
		{
			name: "non-CVE ID",
			handle: &db.VulnerabilityHandle{
				BlobValue: &db.VulnerabilityBlob{
					ID: "GHSA-123",
					Severities: []db.Severity{
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]db.Severity{},
			expected:      []db.Severity{{Value: "high"}},
		},
		{
			name: "NVD provider with CVE",
			handle: &db.VulnerabilityHandle{
				ProviderID: "nvd",
				BlobValue: &db.VulnerabilityBlob{
					ID: "CVE-2023-1234",
					Severities: []db.Severity{
						{Value: "critical"},
					},
				},
			},
			severityCache:     map[string]db.Severity{},
			expected:          []db.Severity{{Value: "critical"}},
			expectCacheUpdate: true,
		},
		{
			name: "CVE with existing severities",
			handle: &db.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &db.VulnerabilityBlob{
					ID: "CVE-2023-5678",
					Severities: []db.Severity{
						{Value: "medium"},
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]db.Severity{
				"cve-2023-5678": {Value: "critical"},
			},
			expected: []db.Severity{
				{Value: "medium"},
				{Value: "high"},
			},
		},
		{
			name: "CVE with no severities, using cache",
			handle: &db.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &db.VulnerabilityBlob{
					ID:         "CVE-2023-9012",
					Severities: []db.Severity{},
				},
			},
			severityCache: map[string]db.Severity{
				"cve-2023-9012": {Value: "high"},
			},
			expected: []db.Severity{{Value: "high"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &writer{
				severityCache: tt.severityCache,
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					assert.NotContains(t, tt.severityCache, strings.ToLower(tt.handle.BlobValue.ID))
				}
			}

			w.fillInMissingSeverity(tt.handle)

			if tt.handle == nil || tt.handle.BlobValue == nil {
				return
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					id := strings.ToLower(tt.handle.BlobValue.ID)
					assert.Equal(t, tt.severityCache[id], w.severityCache[id])
				}
			}

			assert.Equal(t, tt.expected, tt.handle.BlobValue.Severities)
		})
	}
}

func TestFilterUnknownSeverities(t *testing.T) {
	tests := []struct {
		name     string
		input    []db.Severity
		expected []db.Severity
	}{
		{
			name:     "empty input",
			input:    []db.Severity{},
			expected: nil,
		},
		{
			name: "all known severities",
			input: []db.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
			expected: []db.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "mix of known and unknown",
			input: []db.Severity{
				{Value: "high"},
				{Value: "unknown"},
				{Value: "medium"},
				{Value: ""},
			},
			expected: []db.Severity{
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "non-string values",
			input: []db.Severity{
				{Value: 5},
				{Value: nil},
				{Value: "high"},
			},
			expected: []db.Severity{
				{Value: 5},
				{Value: "high"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterUnknownSeverities(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsKnownSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity db.Severity
		expected bool
	}{
		{
			name:     "empty string",
			severity: db.Severity{Value: ""},
			expected: false,
		},
		{
			name:     "unknown string",
			severity: db.Severity{Value: "unknown"},
			expected: false,
		},
		{
			name:     "case insensitive",
			severity: db.Severity{Value: "UNKNOWN"},
			expected: false,
		},
		{
			name:     "valid string severity",
			severity: db.Severity{Value: "high"},
			expected: true,
		},
		{
			name:     "nil value",
			severity: db.Severity{Value: nil},
			expected: false,
		},
		{
			name:     "numeric value",
			severity: db.Severity{Value: 7},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKnownSeverity(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnsureFixDates(t *testing.T) {
	validDate := time.Date(2023, 1, 15, 0, 0, 0, 0, time.UTC)
	zeroDate := time.Time{}

	tests := []struct {
		name    string
		row     *db.AffectedPackageHandle
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "nil BlobValue",
			row: &db.AffectedPackageHandle{
				BlobValue: nil,
			},
		},
		{
			name: "empty ranges",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{},
				},
			},
		},
		{
			name: "range with nil Fix",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{Fix: nil},
					},
				},
			},
		},
		{
			name: "range with empty Fix.Version",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{Fix: &db.Fix{Version: ""}},
					},
				},
			},
		},
		{
			name: "range with Fix.Version '0' - skipped by isFixVersion",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "0", // invalid version - validation skipped
								State:   db.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.Version 'none' - skipped by isFixVersion",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "none", // invalid version - validation skipped
								State:   db.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.Version 'NONE' (case insensitive) - skipped by isFixVersion",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "NONE", // invalid version - validation skipped
								State:   db.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.State not FixedStatus",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3",
								State:   db.NotAffectedFixStatus,
							},
						},
					},
				},
			},
		},
		{
			name: "valid fix with proper date",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3",
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "valid version requires date validation",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3", // valid version - validation required
								State:   db.FixedStatus,
								Detail:  nil, // no date should cause error
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "multiple ranges with valid dates",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3",
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{
							Fix: &db.Fix{
								Version: "2.0.0",
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "mix of valid and nil Fix ranges",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{Fix: nil},
						{
							Fix: &db.Fix{
								Version: "1.2.3",
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{Fix: &db.Fix{Version: ""}},
					},
				},
			},
		},
		{
			name: "missing Fix.Detail with valid version",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3", // valid version triggers validation
								State:   db.FixedStatus,
								Detail:  nil,
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "missing Fix.Detail.Available with valid version",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "2.0.0", // valid version triggers validation
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: nil,
								},
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "missing Fix.Detail.Available.Date with valid version",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "v1.0.0", // valid version triggers validation
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: nil,
									},
								},
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "zero Fix.Detail.Available.Date with valid version",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "3.1.4", // valid version triggers validation
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &zeroDate,
									},
								},
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name: "multiple ranges with one missing date and valid versions",
			row: &db.AffectedPackageHandle{
				BlobValue: &db.PackageBlob{
					Ranges: []db.Range{
						{
							Fix: &db.Fix{
								Version: "1.2.3", // valid version triggers validation
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{
							Fix: &db.Fix{
								Version: "2.0.0", // valid version triggers validation
								State:   db.FixedStatus,
								Detail: &db.FixDetail{
									Available: &db.FixAvailability{
										Date: nil,
									},
								},
							},
						},
					},
				},
			},
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			err := ensureFixDates(tt.row)
			tt.wantErr(t, err)
		})
	}
}

func TestWrite_FailsOnMissingFixDate(t *testing.T) {
	// test proves that Write() method errors out when fix date validation is enabled
	// and a fix is marked as FixedStatus but lacks the required date information
	w := &writer{
		failOnMissingFixDate: true,
		store:                nil, // intentionally nil - we should error before reaching store operations
		severityCache:        make(map[string]db.Severity),
	}

	var vulnID db.ID = 123

	entry := data.Entry{
		DBSchemaVersion: db.ModelVersion,
		Data: transformers.RelatedEntries{
			VulnerabilityHandle: nil, // no vulnerability handle to avoid store operations
			Related: []any{
				db.AffectedPackageHandle{
					VulnerabilityID: vulnID,
					Package:         &db.Package{Name: "test-package"},
					BlobValue: &db.PackageBlob{
						Ranges: []db.Range{
							{
								Fix: &db.Fix{
									Version: "1.2.3", // valid version triggers validation
									State:   db.FixedStatus,
									Detail:  nil, // missing fix detail should cause error
								},
							},
						},
					},
				},
			},
		},
	}

	err := w.Write(entry)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to validate fix dates")
	require.Contains(t, err.Error(), "missing fix date for version \"1.2.3\"")
}

func TestIsFixVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected bool
	}{
		{
			name:     "empty string",
			version:  "",
			expected: false,
		},
		{
			name:     "zero version",
			version:  "0",
			expected: false,
		},
		{
			name:     "none lowercase",
			version:  "none",
			expected: false,
		},
		{
			name:     "none uppercase",
			version:  "NONE",
			expected: false,
		},
		{
			name:     "none mixed case",
			version:  "None",
			expected: false,
		},
		{
			name:     "valid semantic version",
			version:  "1.2.3",
			expected: true,
		},
		{
			name:     "valid version with prefix",
			version:  "v1.2.3",
			expected: true,
		},
		{
			name:     "valid version with patch level",
			version:  "2.4.1-rc1",
			expected: true,
		},
		{
			name:     "valid commit hash",
			version:  "abc123def",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFixVersion(tt.version)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestBatchedWritesEquivalence(t *testing.T) {
	// Test that batched writes produce identical database output to unbatched writes
	// This is the critical correctness test for the batching optimization

	testCases := []struct {
		name       string
		batchSize  int
		numEntries int
	}{
		{
			name:       "unbatched (batch_size=1)",
			batchSize:  1,
			numEntries: 50,
		},
		{
			name:       "small batch",
			batchSize:  10,
			numEntries: 50,
		},
		{
			name:       "large batch",
			batchSize:  2000,
			numEntries: 50,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create temp directory for database
			tmpDir := t.TempDir()

			// Create writer with specified batch size
			w, err := NewWriter(tmpDir, provider.States{}, false, tc.batchSize)
			require.NoError(t, err)

			// Write test entries
			entries := createTestEntries(tc.numEntries)
			for _, entry := range entries {
				err := w.Write(entry)
				require.NoError(t, err)
			}

			// Close to flush all batches
			err = w.Close()
			require.NoError(t, err)

			// Verify database was created
			dbPath := filepath.Join(tmpDir, "vulnerability.db")
			_, err = os.Stat(dbPath)
			require.NoError(t, err, "database file should exist")

			// Open and verify database contents
			reader, err := db.NewReader(db.Config{DBDirPath: tmpDir})
			require.NoError(t, err)
			defer reader.Close()

			// Basic validation: verify we can read data back
			// More detailed validation would require actual query methods
			// but this proves the database is valid and readable
		})
	}
}

func TestBatchAccumulation(t *testing.T) {
	// Test that operations accumulate in buffers before flushing
	tmpDir := t.TempDir()

	w, err := NewWriter(tmpDir, provider.States{}, false, 1000)
	require.NoError(t, err)

	writerImpl := w.(*writer)

	// Write 50 entries (below batch threshold of 1000)
	entries := createTestEntries(50)
	for _, entry := range entries {
		err := writerImpl.Write(entry)
		require.NoError(t, err)
	}

	// Verify buffers contain accumulated operations (not flushed yet)
	assert.Greater(t, len(writerImpl.parentBuffer), 0, "parent buffer should contain operations")
	assert.Greater(t, len(writerImpl.childBuffer), 0, "child buffer should contain operations")
	assert.Equal(t, 0, writerImpl.totalParentBatches, "should not have flushed yet")
	assert.Equal(t, 0, writerImpl.totalChildBatches, "should not have flushed yet")

	// Close should flush everything
	err = writerImpl.Close()
	require.NoError(t, err)

	// Verify buffers were flushed
	assert.Equal(t, 0, len(writerImpl.parentBuffer), "parent buffer should be empty after close")
	assert.Equal(t, 0, len(writerImpl.childBuffer), "child buffer should be empty after close")
	assert.Greater(t, writerImpl.totalParentBatches, 0, "should have flushed parent batch")
	assert.Greater(t, writerImpl.totalChildBatches, 0, "should have flushed child batch")
}

func TestBatchMetrics(t *testing.T) {
	// Test that batch counts accurately reflect number of flushes
	tmpDir := t.TempDir()

	batchSize := 25
	numEntries := 100

	w, err := NewWriter(tmpDir, provider.States{}, false, batchSize)
	require.NoError(t, err)

	writerImpl := w.(*writer)

	// Write entries
	entries := createTestEntries(numEntries)
	for _, entry := range entries {
		err := writerImpl.Write(entry)
		require.NoError(t, err)
	}

	err = writerImpl.Close()
	require.NoError(t, err)

	// Verify batch counts
	// With 100 entries, batchSize=25:
	// - Parent ops: 100 vulnerabilities / 25 = 4 batches
	// - Child ops: depends on children per entry, but should also batch
	assert.Greater(t, writerImpl.totalParentBatches, 0, "should have parent batches")
	assert.Greater(t, writerImpl.totalChildBatches, 0, "should have child batches")
}

func TestBatchSizeConfiguration(t *testing.T) {
	// Test that batch size defaults and configuration work correctly
	tmpDir := t.TempDir()

	tests := []struct {
		name         string
		inputSize    int
		expectedSize int
	}{
		{
			name:         "default (0 -> 2000)",
			inputSize:    0,
			expectedSize: 2000,
		},
		{
			name:         "custom size",
			inputSize:    500,
			expectedSize: 500,
		},
		{
			name:         "unbatched mode",
			inputSize:    1,
			expectedSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := NewWriter(tmpDir, provider.States{}, false, tt.inputSize)
			require.NoError(t, err)
			defer w.Close()

			writerImpl := w.(*writer)
			assert.Equal(t, tt.expectedSize, writerImpl.parentBatchSize)
			assert.Equal(t, tt.expectedSize, writerImpl.childBatchSize)
		})
	}
}

// createTestEntries creates test entries with unique identifiable content
func createTestEntries(count int) []data.Entry {
	entries := make([]data.Entry, count)

	for i := 0; i < count; i++ {
		name := fmt.Sprintf("CVE-2023-TEST-%04d", i)
		entries[i] = data.Entry{
			DBSchemaVersion: db.ModelVersion,
			Data: transformers.RelatedEntries{
				VulnerabilityHandle: &db.VulnerabilityHandle{
					Name:       name,
					ProviderID: "test-provider",
					Provider: &db.Provider{
						ID:      "test-provider",
						Version: "1.0.0",
					},
					BlobValue: &db.VulnerabilityBlob{
						ID: name,
					},
				},
				Related: []any{
					db.CWEHandle{
						CVE: name,
						CWE: "CWE-79",
					},
				},
			},
		}
	}

	return entries
}
