package distribution

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/schemaver"
)

func TestNewLatestDocument(t *testing.T) {
	t.Run("valid entries", func(t *testing.T) {
		archive1 := Archive{
			Description: db.Description{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Built:         db.Time{Time: time.Now()},
			},
		}
		archive2 := Archive{
			Description: db.Description{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Built:         db.Time{Time: time.Now().Add(-1 * time.Hour)},
			},
		}

		latestDoc := NewLatestDocument(archive1, archive2)
		require.NotNil(t, latestDoc)
		require.Equal(t, latestDoc.Archive, archive1) // most recent archive
		require.Equal(t, latestDoc.SchemaVersion.Model, db.ModelVersion)
	})

	t.Run("filter entries", func(t *testing.T) {
		archive1 := Archive{
			Description: db.Description{
				SchemaVersion: schemaver.New(5, db.Revision, db.Addition), // old!
				Built:         db.Time{Time: time.Now()},
			},
		}
		archive2 := Archive{
			Description: db.Description{
				SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
				Built:         db.Time{Time: time.Now().Add(-1 * time.Hour)},
			},
		}

		latestDoc := NewLatestDocument(archive1, archive2)
		require.NotNil(t, latestDoc)
		require.Equal(t, latestDoc.Archive, archive2) // most recent archive with valid version
		require.Equal(t, latestDoc.SchemaVersion.Model, db.ModelVersion)
	})

	t.Run("no entries", func(t *testing.T) {
		latestDoc := NewLatestDocument()
		require.Nil(t, latestDoc)
	})
}

func TestNewLatestFromReader(t *testing.T) {

	t.Run("valid JSON", func(t *testing.T) {
		latestDoc := LatestDocument{
			Archive: Archive{
				Description: db.Description{
					SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					Built:         db.Time{Time: time.Now().Truncate(time.Second).UTC()},
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

	t.Run("empty", func(t *testing.T) {
		emptyJSON := []byte("{}")
		val, err := NewLatestFromReader(bytes.NewReader(emptyJSON))
		require.NoError(t, err)
		assert.Nil(t, val)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		invalidJSON := []byte("invalid json")
		val, err := NewLatestFromReader(bytes.NewReader(invalidJSON))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse DB latest.json")
		assert.Nil(t, val)
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
				Archive: Archive{
					Description: db.Description{
						Built:         now,
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "sha256:validchecksum",
				},
				// note: status not supplied, should assume to be active
			},
			expectedError: require.NoError,
		},
		{
			name: "explicit status",
			latestDoc: LatestDocument{
				Archive: Archive{
					Description: db.Description{
						Built:         now,
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
						Built: now,
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
				Archive: Archive{
					Description: db.Description{
						Built:         now,
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
				Archive: Archive{
					Description: db.Description{
						Built:         now,
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
				Archive: Archive{
					Description: db.Description{
						Built:         db.Time{}, // this!
						SchemaVersion: schemaver.New(db.ModelVersion, db.Revision, db.Addition),
					},
					Path:     "valid/path/to/archive",
					Checksum: "xxh64:validchecksum",
				},
				Status: "active",
			},
			expectedError: errContains("missing built time"),
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
			assert.Equal(t, tt.latestDoc.Archive.Checksum, result.Archive.Checksum, "archive checksum mismatch")
			assert.Equal(t, tt.latestDoc.Archive.Description.Built.Time, result.Archive.Description.Built.Time, "built time mismatch")
			assert.Equal(t, tt.latestDoc.Archive.Path, result.Archive.Path, "path mismatch")
			if tt.latestDoc.Status == "" {
				assert.Equal(t, StatusActive, result.Status, "status mismatch")
			} else {
				assert.Equal(t, tt.latestDoc.Status, result.Status, "status mismatch")
			}
		})
	}
}

func TestNewArchive(t *testing.T) {
	tests := []struct {
		name      string
		contents  string
		time      time.Time
		model     int
		revision  int
		addition  int
		expectErr require.ErrorAssertionFunc
		expected  *Archive
	}{
		{
			name:      "valid input",
			contents:  "test archive content",
			time:      time.Date(2023, 11, 24, 12, 0, 0, 0, time.UTC),
			model:     1,
			revision:  0,
			addition:  5,
			expectErr: require.NoError,
			expected: &Archive{
				Description: db.Description{
					SchemaVersion: schemaver.New(1, 0, 5),
					Built:         db.Time{Time: time.Date(2023, 11, 24, 12, 0, 0, 0, time.UTC)},
				},
				Path:     "archive.tar.gz",
				Checksum: "sha256:2a11c11d2c3803697c458a1f5f03c2b73235c101f93c88193cc8810003c40d87",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			tempFile, err := os.Create(filepath.Join(d, tt.expected.Path))
			require.NoError(t, err)
			_, err = tempFile.WriteString(tt.contents)
			require.NoError(t, err)

			archive, err := NewArchive(tempFile.Name(), tt.time, tt.model, tt.revision, tt.addition)
			tt.expectErr(t, err)
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.expected, archive); diff != "" {
				t.Errorf("unexpected archive (-want +got):\n%s", diff)
			}
		})
	}
}
