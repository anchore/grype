package commands

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/internal/schemaver"
)

func Test_ListingUserAgent(t *testing.T) {

	t.Run("legacy", func(t *testing.T) {
		listingFile := "/listing.json"

		got := ""

		// setup mock
		handler := http.NewServeMux()
		handler.HandleFunc(listingFile, func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("User-Agent")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("1.0.0"))
		})
		mockSrv := httptest.NewServer(handler)
		defer mockSrv.Close()

		dbOptions := *options.DefaultDatabaseCommand(clio.Identification{
			Name:    "the-app",
			Version: "v3.2.1",
		})
		dbOptions.DB.RequireUpdateCheck = true
		dbOptions.DB.UpdateURL = mockSrv.URL + listingFile

		_ = legacyDBList(dbListOptions{
			Output:          "",
			DatabaseCommand: dbOptions,
		})

		if got != "the-app v3.2.1" {
			t.Errorf("expected User-Agent header to match, got: %v", got)
		}
	})

	t.Run("new", func(t *testing.T) {
		listingFile := "/latest.json"

		got := ""

		// setup mock
		handler := http.NewServeMux()
		handler.HandleFunc(listingFile, func(w http.ResponseWriter, r *http.Request) {
			got = r.Header.Get("User-Agent")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(&distribution.LatestDocument{
				Status: "active",
				Archive: distribution.Archive{
					Description: db.Description{
						SchemaVersion: schemaver.New(6, 0, 0),
						Built:         db.Time{Time: time.Now()},
					},
					Path:     "vulnerability-db_v6.0.0.tar.gz",
					Checksum: "sha256:dummychecksum",
				},
			})
		})
		mockSrv := httptest.NewServer(handler)
		defer mockSrv.Close()

		dbOptions := *options.DefaultDatabaseCommand(clio.Identification{
			Name:    "new-app",
			Version: "v4.0.0",
		})
		dbOptions.DB.RequireUpdateCheck = true
		dbOptions.DB.UpdateURL = mockSrv.URL + listingFile

		err := newDBList(dbListOptions{
			Output:          textOutputFormat,
			DatabaseCommand: dbOptions,
		})
		require.NoError(t, err)

		if got != "new-app v4.0.0" {
			t.Errorf("expected User-Agent header to match, got: %v", got)
		}
	})

}

func TestPresentNewDBList(t *testing.T) {
	baseURL := "http://localhost:8000/latest.json"
	latestDoc := &distribution.LatestDocument{
		Status: "active",
		Archive: distribution.Archive{
			Description: db.Description{
				SchemaVersion: schemaver.New(6, 0, 0),
				Built:         db.Time{Time: time.Date(2024, 11, 27, 14, 43, 17, 0, time.UTC)},
			},
			Path:     "vulnerability-db_v6.0.0_2024-11-25T01:31:56Z_1732718597.tar.zst",
			Checksum: "sha256:16bcb6551c748056f752f299fcdb4fa50fe61589d086be3889e670261ff21ca4",
		},
	}

	tests := []struct {
		name         string
		format       string
		latest       *distribution.LatestDocument
		expectedText string
		expectedErr  require.ErrorAssertionFunc
	}{
		{
			name:   "valid text format",
			format: textOutputFormat,
			latest: latestDoc,
			expectedText: `Status:   active
Schema:   v6.0.0
Built:    2024-11-27T14:43:17Z
Listing:  http://localhost:8000/latest.json
DB URL:   http://localhost:8000/vulnerability-db_v6.0.0_2024-11-25T01:31:56Z_1732718597.tar.zst
Checksum: sha256:16bcb6551c748056f752f299fcdb4fa50fe61589d086be3889e670261ff21ca4
`,
			expectedErr: require.NoError,
		},
		{
			name:   "valid JSON format",
			format: jsonOutputFormat,
			latest: latestDoc,
			expectedText: `{
 "status": "active",
 "schemaVersion": "v6.0.0",
 "built": "2024-11-27T14:43:17Z",
 "path": "vulnerability-db_v6.0.0_2024-11-25T01:31:56Z_1732718597.tar.zst",
 "checksum": "sha256:16bcb6551c748056f752f299fcdb4fa50fe61589d086be3889e670261ff21ca4"
}
`,
			expectedErr: require.NoError,
		},
		{
			name:        "nil latest document",
			format:      textOutputFormat,
			latest:      nil,
			expectedErr: requireErrorContains("no database listing found"),
		},
		{
			name:        "unsupported format",
			format:      "unsupported",
			latest:      latestDoc,
			expectedErr: requireErrorContains("unsupported output format"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &bytes.Buffer{}

			err := presentNewDBList(tt.format, baseURL, writer, tt.latest)
			if tt.expectedErr == nil {
				tt.expectedErr = require.NoError
			}
			tt.expectedErr(t, err)

			if err != nil {
				return
			}

			require.Equal(t, strings.TrimSpace(tt.expectedText), strings.TrimSpace(writer.String()))
		})
	}
}
