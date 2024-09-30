package distribution

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	db "github.com/anchore/grype/grype/db/v6"
)

func TestClient_LatestFromURL(t *testing.T) {
	tests := []struct {
		name        string
		setupServer func() *httptest.Server
		expectedDoc *LatestDocument
		expectedErr require.ErrorAssertionFunc
	}{
		{
			name: "go case",
			setupServer: func() *httptest.Server {
				doc := LatestDocument{
					SchemaVersion: "1.0.0",
					Status:        "active",
					Archive: Archive{
						Description: db.Description{
							SchemaVersion: "1.0.0",
							Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
							Checksum:      "xxh64:dummychecksum",
						},
						Path:     "path/to/archive",
						Checksum: "checksum123",
					},
				}
				data, _ := json.Marshal(doc)

				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Header().Set("Content-Type", "application/json")
					_, err := w.Write(data)
					require.NoError(t, err)
				}))
			},
			expectedDoc: &LatestDocument{
				SchemaVersion: "1.0.0",
				Status:        "active",
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: "1.0.0",
						Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
						Checksum:      "xxh64:dummychecksum",
					},
					Path:     "path/to/archive",
					Checksum: "checksum123",
				},
			},
		},
		{
			name: "error response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			expectedDoc: nil,
			expectedErr: func(t require.TestingT, err error, _ ...interface{}) {
				require.Error(t, err)
				require.Contains(t, err.Error(), "500 Internal Server Error")
			},
		},
		{
			name: "malformed JSON response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte("malformed json"))
					require.NoError(t, err)
				}))
			},
			expectedDoc: nil,
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

			server := tt.setupServer()
			defer server.Close()

			c, err := NewClient(Config{
				LatestURL: server.URL,
			})
			require.NoError(t, err)

			cl := c.(client)

			doc, err := cl.latestFromURL()
			tt.expectedErr(t, err)
			if err != nil {
				return
			}

			require.Equal(t, tt.expectedDoc, doc)
		})
	}
}

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
		cl.updateDownloader = mg

		return cl, mg
	}

	t.Run("successful download", func(t *testing.T) {
		c, mg := setup()
		mg.On("GetToDir", mock.Anything, "http://localhost:8080/path/to/archive.tar.gz?checksum=checksum123", mock.Anything).Return(nil)

		tempDir, err := c.Download(*archive, destDir, &progress.Manual{})
		require.NoError(t, err)
		require.True(t, len(tempDir) > 0)

		mg.AssertExpectations(t)
	})

	t.Run("download error", func(t *testing.T) {
		c, mg := setup()
		mg.On("GetToDir", mock.Anything, "http://localhost:8080/path/to/archive.tar.gz?checksum=checksum123", mock.Anything).Return(errors.New("download failed"))

		tempDir, err := c.Download(*archive, destDir, &progress.Manual{})
		require.Error(t, err)
		require.Empty(t, tempDir)
		require.Contains(t, err.Error(), "unable to download db")

		mg.AssertExpectations(t)
	})
}

func TestClient_IsUpdateAvailable(t *testing.T) {
	current := &db.Description{
		SchemaVersion: "1.0.0",
		Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
	}

	tests := []struct {
		name            string
		candidate       *LatestDocument
		expectedArchive *Archive
		expectedErr     require.ErrorAssertionFunc
	}{
		{
			name: "update available",
			candidate: &LatestDocument{
				SchemaVersion: "1.0.0",
				Status:        "active",
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: "1.0.0",
						Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
						Checksum:      "xxh64:dummychecksum",
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			expectedArchive: &Archive{
				Description: db.Description{
					SchemaVersion: "1.0.0",
					Built:         db.Time{Time: time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)},
					Checksum:      "xxh64:dummychecksum",
				},
				Path:     "path/to/archive.tar.gz",
				Checksum: "checksum123",
			},
			expectedErr: nil,
		},
		{
			name: "no update available",
			candidate: &LatestDocument{
				SchemaVersion: "1.0.0",
				Status:        "active",
				Archive: Archive{
					Description: db.Description{
						SchemaVersion: "1.0.0",
						Built:         db.Time{Time: time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)},
						Checksum:      "xxh64:dummychecksum",
					},
					Path:     "path/to/archive.tar.gz",
					Checksum: "checksum123",
				},
			},
			expectedArchive: nil,
			expectedErr:     nil,
		},
		{
			name:            "no candidate available",
			candidate:       nil,
			expectedArchive: nil,
			expectedErr:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectedErr == nil {
				tt.expectedErr = require.NoError
			}
			c, err := NewClient(Config{})
			require.NoError(t, err)

			cl := c.(client)

			archive, err := cl.isUpdateAvailable(current, tt.candidate)

			tt.expectedErr(t, err)
			if err != nil {
				return
			}

			require.Equal(t, tt.expectedArchive, archive)
		})
	}
}

func TestDatabaseDescription_IsSupersededBy(t *testing.T) {
	t1 := time.Date(2023, 9, 26, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2023, 9, 27, 12, 0, 0, 0, time.UTC)

	currentMetadata := db.Description{
		SchemaVersion: "1.0.0",
		Built:         db.Time{Time: t1},
	}

	newerMetadata := db.Description{
		SchemaVersion: "1.0.0",
		Built:         db.Time{Time: t2},
	}

	olderMetadata := db.Description{
		SchemaVersion: "1.0.0",
		Built:         db.Time{Time: t1},
	}

	differentModelMetadata := db.Description{
		SchemaVersion: "2.0.0",
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
