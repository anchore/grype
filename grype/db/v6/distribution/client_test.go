package distribution

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/internal/schemaver"
)

type mockGetter struct {
	mock.Mock
}

func (m *mockGetter) GetFile(dst, src string, manuals ...*progress.Manual) error {
	args := m.Called(dst, src, manuals)
	return args.Error(0)
}

func (m *mockGetter) GetToDir(dst, src string, manuals ...*progress.Manual) error {
	args := m.Called(dst, src, manuals)
	return args.Error(0)
}

func TestClient_Latest(t *testing.T) {
	tests := []struct {
		name           string
		latestResponse []byte
		getFileErr     error
		expectedDoc    *LatestDocument
		expectedErr    require.ErrorAssertionFunc
	}{
		{
			name: "go case",
			latestResponse: func() []byte {
				doc := LatestDocument{
					Status: "active",
					Archive: Archive{
						Description: db.Description{
							SchemaVersion: schemaver.New(1, 0, 0),
							Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
						},
						Path:     "path/to/archive",
						Checksum: "checksum123",
					},
				}
				data, err := json.Marshal(doc)
				require.NoError(t, err)
				return data
			}(),
			expectedDoc: &LatestDocument{
				Status: "active",
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(1, 0, 0),
						Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
					},
					Path:     "path/to/archive",
					Checksum: "checksum123",
				},
			},
		},
		{
			name:        "download error",
			getFileErr:  errors.New("failed to download file"),
			expectedDoc: nil,
			expectedErr: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "unable to download listing")
			},
		},
		{
			name:           "malformed JSON response",
			latestResponse: []byte("malformed json"),
			expectedDoc:    nil,
			expectedErr: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "invalid character 'm' looking for beginning of value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedErr == nil {
				tt.expectedErr = require.NoError
			}
			mockFs := afero.NewMemMapFs()

			mg := new(mockGetter)

			mg.On("GetFile", mock.Anything, "http://localhost:8080/latest.json", mock.Anything).Run(func(args mock.Arguments) {
				if tt.getFileErr != nil {
					return
				}

				dst := args.String(0)
				err := afero.WriteFile(mockFs, dst, tt.latestResponse, 0644)
				require.NoError(t, err)
			}).Return(tt.getFileErr)

			c, err := NewClient(Config{
				LatestURL: "http://localhost:8080/latest.json",
			})
			require.NoError(t, err)

			cl := c.(client)
			cl.fs = mockFs
			cl.listingDownloader = mg

			doc, err := cl.Latest()
			tt.expectedErr(t, err)
			if err != nil {
				return
			}

			require.Equal(t, tt.expectedDoc, doc)
			mg.AssertExpectations(t)
		})
	}
}

func TestClient_Download(t *testing.T) {
	destDir := t.TempDir()
	archive := &Archive{
		Path:     "path/to/archive.tar.gz",
		Checksum: "checksum123",
	}

	setup := func() (Client, *mockGetter) {
		mg := new(mockGetter)

		c, err := NewClient(Config{
			LatestURL: "http://localhost:8080/latest.json",
		})
		require.NoError(t, err)

		cl := c.(client)
		cl.dbDownloader = mg

		return cl, mg
	}

	t.Run("successful download", func(t *testing.T) {
		c, mg := setup()
		url := "http://localhost:8080/path/to/archive.tar.gz?checksum=checksum123"
		mg.On("GetToDir", mock.Anything, url, mock.Anything).Return(nil)

		tempDir, actualURL, err := c.Download(*archive, destDir, &progress.Manual{})
		require.NoError(t, err)
		require.True(t, len(tempDir) > 0)
		assert.Equal(t, url, actualURL)

		mg.AssertExpectations(t)
	})

	t.Run("download error", func(t *testing.T) {
		c, mg := setup()
		url := "http://localhost:8080/path/to/archive.tar.gz?checksum=checksum123"
		mg.On("GetToDir", mock.Anything, url, mock.Anything).Return(errors.New("download failed"))

		tempDir, actualURL, err := c.Download(*archive, destDir, &progress.Manual{})
		require.Error(t, err)
		require.Empty(t, tempDir)
		require.Contains(t, err.Error(), "unable to download db")
		assert.Empty(t, actualURL)

		mg.AssertExpectations(t)
	})

	t.Run("nested into dir that does not exist", func(t *testing.T) {
		c, mg := setup()
		url := "http://localhost:8080/path/to/archive.tar.gz?checksum=checksum123"
		mg.On("GetToDir", mock.Anything, url, mock.Anything).Return(nil)

		nestedPath := filepath.Join(destDir, "nested")
		tempDir, actualURL, err := c.Download(*archive, nestedPath, &progress.Manual{})
		require.NoError(t, err)
		require.True(t, len(tempDir) > 0)
		assert.Equal(t, url, actualURL)

		mg.AssertExpectations(t)
	})
}

func TestClient_IsUpdateAvailable(t *testing.T) {
	current := &db.Description{
		SchemaVersion: schemaver.New(1, 0, 0),
		Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
	}

	tests := []struct {
		name      string
		candidate *LatestDocument
		archive   *Archive
		message   string
	}{
		{
			name: "update available",
			candidate: &LatestDocument{
				Status: StatusActive,
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(1, 0, 0),
						Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			archive: &Archive{
				Description: db.Description{
					SchemaVersion: schemaver.New(1, 0, 0),
					Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
				},
				Path:     "path/to/archive.tar.gz",
				Checksum: "checksum123",
			},
		},
		{
			name: "no update available",
			candidate: &LatestDocument{
				Status: "active",
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(1, 0, 0),
						Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			archive: nil,
		},
		{
			name:      "no candidate available",
			candidate: nil,
			archive:   nil,
		},
		{
			name: "candidate deprecated",
			candidate: &LatestDocument{
				Status: StatusDeprecated,
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(1, 0, 0),
						Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			archive: &Archive{
				Description: db.Description{
					SchemaVersion: schemaver.New(1, 0, 0),
					Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
				},
				Path:     "path/to/archive.tar.gz",
				Checksum: "checksum123",
			},
			message: "this version of grype will soon stop receiving vulnerability database updates, please update grype",
		},
		{
			name: "candidate end of life",
			candidate: &LatestDocument{
				Status: StatusEndOfLife,
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(1, 0, 0),
						Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			archive: &Archive{
				Description: db.Description{
					SchemaVersion: schemaver.New(1, 0, 0),
					Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
				},
				Path:     "path/to/archive.tar.gz",
				Checksum: "checksum123",
			},
			message: "this version of grype is no longer receiving vulnerability database updates, please update grype",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(Config{})
			require.NoError(t, err)

			cl := c.(client)

			archive, message := cl.isUpdateAvailable(current, tt.candidate)
			assert.Equal(t, tt.message, message)
			assert.Equal(t, tt.archive, archive)
		})
	}
}

func TestDatabaseDescription_IsSupersededBy(t *testing.T) {
	t1 := time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)

	currentMetadata := db.Description{
		SchemaVersion: schemaver.New(1, 0, 0),
		Built:         db.Time{Time: t1},
	}

	newerMetadata := db.Description{
		SchemaVersion: schemaver.New(1, 0, 0),
		Built:         db.Time{Time: t2},
	}

	olderMetadata := db.Description{
		SchemaVersion: schemaver.New(1, 0, 0),
		Built:         db.Time{Time: t1},
	}

	differentModelMetadata := db.Description{
		SchemaVersion: schemaver.New(2, 0, 0),
		Built:         db.Time{Time: t2},
	}

	tests := []struct {
		name     string
		current  *db.Description
		other    db.Description
		expected bool
	}{
		{
			name:     "no current metadata",
			current:  nil,
			other:    newerMetadata,
			expected: true,
		},
		{
			name:     "newer build",
			current:  &currentMetadata,
			other:    newerMetadata,
			expected: true,
		},
		{
			name:     "older build",
			current:  &currentMetadata,
			other:    olderMetadata,
			expected: false,
		},
		{
			name:     "different schema version",
			current:  &currentMetadata,
			other:    differentModelMetadata,
			expected: false,
		},
		{
			name:     "current metadata has no schema version",
			current:  &db.Description{Built: db.Time{Time: t1}},
			other:    newerMetadata,
			expected: false,
		},
		{
			name:     "update has no schema version",
			current:  &currentMetadata,
			other:    db.Description{Built: db.Time{Time: t2}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSupersededBy(tt.current, tt.other)
			require.Equal(t, tt.expected, result)
		})
	}
}

func Test_latestURL(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{
			url:      "https://grype.anchore.io/databases",
			expected: "https://grype.anchore.io/databases/v6/latest.json",
		},
		{
			url:      "https://grype.anchore.io/databases/",
			expected: "https://grype.anchore.io/databases/v6/latest.json",
		},
		{
			url:      "https://grype.anchore.io/databases/v6/latest.json",
			expected: "https://grype.anchore.io/databases/v6/latest.json",
		},
		{
			url:      "http://grype.anchore.io/databases/",
			expected: "http://grype.anchore.io/databases/v6/latest.json",
		},
		{
			url:      "https://example.com/file.json",
			expected: "https://example.com/file.json",
		},
	}

	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			c := client{
				config: Config{
					LatestURL: test.url,
				},
			}
			got := c.latestURL()
			require.Equal(t, test.expected, got)
		})
	}
}
