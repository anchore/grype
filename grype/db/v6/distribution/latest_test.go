package distribution

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/schemaver"
	db "github.com/anchore/grype/grype/db/v6"
)

func TestNewLatestDocument(t *testing.T) {
	t.Run("valid entries", func(t *testing.T) {
		archive1 := Archive{
			Description: db.Description{
				Built: db.Time{Time: time.Now()},
			},
		}
		archive2 := Archive{
			Description: db.Description{
				Built: db.Time{Time: time.Now().Add(-1 * time.Hour)},
			},
		}

		latestDoc := NewLatestDocument(archive1, archive2)
		require.NotNil(t, latestDoc)
		require.Equal(t, latestDoc.Archive, archive1) // most recent archive
		actual, ok := latestDoc.SchemaVersion.ModelPart()
		require.True(t, ok)
		require.Equal(t, actual, db.ModelVersion)
	})

	t.Run("no entries", func(t *testing.T) {
		latestDoc := NewLatestDocument()
		require.Nil(t, latestDoc)
	})
}

func TestNewLatestFromReader(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		latestDoc := LatestDocument{
			SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
			Archive: Archive{
				Description: db.Description{
					Built: db.Time{Time: time.Now().Truncate(time.Second).UTC()},
				},
			},
			Status: "active",
		}

		var buf bytes.Buffer
		require.NoError(t, json.NewEncoder(&buf).Encode(latestDoc))

		result, err := NewLatestFromReader(&buf)
		require.NoError(t, err)
		require.Equal(t, latestDoc.SchemaVersion, result.SchemaVersion)
		require.Equal(t, latestDoc.Archive.Description.Built.Time, result.Archive.Description.Built.Time)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte("invalid json")
		_, err := NewLatestFromReader(bytes.NewReader(invalidJSON))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse DB latest.json")
	})
}

func TestLatestDocument_Write(t *testing.T) {

	errContains := func(text string) require.ErrorAssertionFunc {
		return func(t require.TestingT, err error, msgAndArgs ...interface{}) {
			require.ErrorContains(t, err, text, msgAndArgs...)
		}
	}

	now := db.Time{Time: time.Now().Truncate(time.Second).UTC()}

	tests := []struct {
		name          string
		latestDoc     LatestDocument
		expectedError require.ErrorAssertionFunc
	}{
		{
			name: "valid document",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				// note: status not supplied, should assume to be active
			},
			expectedError: require.NoError,
		},
		{
			name: "explicit status",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				Status: StatusDeprecated,
			},
			expectedError: require.NoError,
		},
		{
			name: "missing schema version",
			latestDoc: LatestDocument{
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				Status: "active",
			},
			expectedError: errContains("missing schema version"),
		},
		{
			name: "missing archive path",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "", // this!
					Checksum: "xxh64:validchecksum",
				},
				Status: "active",
			},
			expectedError: errContains("missing archive path"),
		},
		{
			name: "missing archive checksum",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "", // this!
				},
				Status: "active",
			},
			expectedError: errContains("missing archive checksum"),
		},
		{
			name: "missing built time",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         db.Time{}, // this!
						Checksum:      "xxh64:validchecksum",
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				Status: "active",
			},
			expectedError: errContains("missing built time"),
		},
		{
			name: "missing database checksum",
			latestDoc: LatestDocument{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						Checksum:      "", // this!
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				Status: "active",
			},
			expectedError: errContains("missing database checksum"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedError == nil {
				tt.expectedError = require.NoError
			}
			var buf bytes.Buffer
			err := tt.latestDoc.Write(&buf)
			tt.expectedError(t, err)
			if err != nil {
				return
			}

			var result LatestDocument
			assert.NoError(t, json.Unmarshal(buf.Bytes(), &result))
			assert.Equal(t, tt.latestDoc.SchemaVersion, result.SchemaVersion, "schema version mismatch")
			assert.Empty(t, result.Archive.Description.SchemaVersion, "nested schema version should be empty")
			assert.Equal(t, tt.latestDoc.Archive.Checksum, result.Archive.Checksum, "archive checksum mismatch")
			assert.Equal(t, tt.latestDoc.Archive.Description.Built.Time, result.Archive.Description.Built.Time, "built time mismatch")
			assert.Equal(t, tt.latestDoc.Archive.Description.Checksum, result.Archive.Description.Checksum, "database checksum mismatch")
			assert.Equal(t, tt.latestDoc.Archive.Path, result.Archive.Path, "path mismatch")
			if tt.latestDoc.Status == "" {
				assert.Equal(t, StatusActive, result.Status, "status mismatch")
			} else {
				assert.Equal(t, tt.latestDoc.Status, result.Status, "status mismatch")
			}
		})
	}
}
