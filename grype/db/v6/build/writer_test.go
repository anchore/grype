package v6

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data"
	grypeDB "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

func TestFillInMissingSeverity(t *testing.T) {
	tests := []struct {
		name              string
		handle            *grypeDB.VulnerabilityHandle
		severityCache     map[string]grypeDB.Severity
		expected          []grypeDB.Severity
		expectCacheUpdate bool
	}{
		{
			name:          "nil handle",
			handle:        nil,
			severityCache: map[string]grypeDB.Severity{},
			expected:      nil,
		},
		{
			name: "nil metadata",
			handle: &grypeDB.VulnerabilityHandle{
				BlobValue: nil,
			},
			severityCache: map[string]grypeDB.Severity{},
			expected:      nil,
		},
		{
			name: "non-CVE ID",
			handle: &grypeDB.VulnerabilityHandle{
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "GHSA-123",
					Severities: []grypeDB.Severity{
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]grypeDB.Severity{},
			expected:      []grypeDB.Severity{{Value: "high"}},
		},
		{
			name: "NVD provider with CVE",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "nvd",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "CVE-2023-1234",
					Severities: []grypeDB.Severity{
						{Value: "critical"},
					},
				},
			},
			severityCache:     map[string]grypeDB.Severity{},
			expected:          []grypeDB.Severity{{Value: "critical"}},
			expectCacheUpdate: true,
		},
		{
			name: "CVE with existing severities",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID: "CVE-2023-5678",
					Severities: []grypeDB.Severity{
						{Value: "medium"},
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]grypeDB.Severity{
				"cve-2023-5678": {Value: "critical"},
			},
			expected: []grypeDB.Severity{
				{Value: "medium"},
				{Value: "high"},
			},
		},
		{
			name: "CVE with no severities, using cache",
			handle: &grypeDB.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &grypeDB.VulnerabilityBlob{
					ID:         "CVE-2023-9012",
					Severities: []grypeDB.Severity{},
				},
			},
			severityCache: map[string]grypeDB.Severity{
				"cve-2023-9012": {Value: "high"},
			},
			expected: []grypeDB.Severity{{Value: "high"}},
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
		input    []grypeDB.Severity
		expected []grypeDB.Severity
	}{
		{
			name:     "empty input",
			input:    []grypeDB.Severity{},
			expected: nil,
		},
		{
			name: "all known severities",
			input: []grypeDB.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
			expected: []grypeDB.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "mix of known and unknown",
			input: []grypeDB.Severity{
				{Value: "high"},
				{Value: "unknown"},
				{Value: "medium"},
				{Value: ""},
			},
			expected: []grypeDB.Severity{
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "non-string values",
			input: []grypeDB.Severity{
				{Value: 5},
				{Value: nil},
				{Value: "high"},
			},
			expected: []grypeDB.Severity{
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
		severity grypeDB.Severity
		expected bool
	}{
		{
			name:     "empty string",
			severity: grypeDB.Severity{Value: ""},
			expected: false,
		},
		{
			name:     "unknown string",
			severity: grypeDB.Severity{Value: "unknown"},
			expected: false,
		},
		{
			name:     "case insensitive",
			severity: grypeDB.Severity{Value: "UNKNOWN"},
			expected: false,
		},
		{
			name:     "valid string severity",
			severity: grypeDB.Severity{Value: "high"},
			expected: true,
		},
		{
			name:     "nil value",
			severity: grypeDB.Severity{Value: nil},
			expected: false,
		},
		{
			name:     "numeric value",
			severity: grypeDB.Severity{Value: 7},
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
		row     *grypeDB.AffectedPackageHandle
		wantErr require.ErrorAssertionFunc
	}{
		{
			name: "nil BlobValue",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: nil,
			},
		},
		{
			name: "empty ranges",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{},
				},
			},
		},
		{
			name: "range with nil Fix",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{Fix: nil},
					},
				},
			},
		},
		{
			name: "range with empty Fix.Version",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{Fix: &grypeDB.Fix{Version: ""}},
					},
				},
			},
		},
		{
			name: "range with Fix.Version '0' - skipped by isFixVersion",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "0", // invalid version - validation skipped
								State:   grypeDB.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.Version 'none' - skipped by isFixVersion",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "none", // invalid version - validation skipped
								State:   grypeDB.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.Version 'NONE' (case insensitive) - skipped by isFixVersion",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "NONE", // invalid version - validation skipped
								State:   grypeDB.FixedStatus,
								Detail:  nil, // no date but should not error
							},
						},
					},
				},
			},
		},
		{
			name: "range with Fix.State not FixedStatus",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3",
								State:   grypeDB.NotAffectedFixStatus,
							},
						},
					},
				},
			},
		},
		{
			name: "valid fix with proper date",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3",
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3", // valid version - validation required
								State:   grypeDB.FixedStatus,
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3",
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{
							Fix: &grypeDB.Fix{
								Version: "2.0.0",
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{Fix: nil},
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3",
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{Fix: &grypeDB.Fix{Version: ""}},
					},
				},
			},
		},
		{
			name: "missing Fix.Detail with valid version",
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3", // valid version triggers validation
								State:   grypeDB.FixedStatus,
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "2.0.0", // valid version triggers validation
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "v1.0.0", // valid version triggers validation
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "3.1.4", // valid version triggers validation
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
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
			row: &grypeDB.AffectedPackageHandle{
				BlobValue: &grypeDB.PackageBlob{
					Ranges: []grypeDB.Range{
						{
							Fix: &grypeDB.Fix{
								Version: "1.2.3", // valid version triggers validation
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
										Date: &validDate,
									},
								},
							},
						},
						{
							Fix: &grypeDB.Fix{
								Version: "2.0.0", // valid version triggers validation
								State:   grypeDB.FixedStatus,
								Detail: &grypeDB.FixDetail{
									Available: &grypeDB.FixAvailability{
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
		severityCache:        make(map[string]grypeDB.Severity),
	}

	var vulnID grypeDB.ID = 123

	entry := data.Entry{
		DBSchemaVersion: grypeDB.ModelVersion,
		Data: transformers.RelatedEntries{
			VulnerabilityHandle: nil, // no vulnerability handle to avoid store operations
			Related: []any{
				grypeDB.AffectedPackageHandle{
					VulnerabilityID: vulnID,
					Package:         &grypeDB.Package{Name: "test-package"},
					BlobValue: &grypeDB.PackageBlob{
						Ranges: []grypeDB.Range{
							{
								Fix: &grypeDB.Fix{
									Version: "1.2.3", // valid version triggers validation
									State:   grypeDB.FixedStatus,
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
