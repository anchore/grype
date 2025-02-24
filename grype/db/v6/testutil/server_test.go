package dbtest_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/distribution"
	dbtest "github.com/anchore/grype/grype/db/v6/testutil"
)

func Test_NewServer(t *testing.T) {
	tests := []struct {
		name         string
		useDefault   bool
		serverSubdir string
	}{
		{
			name:       "default path",
			useDefault: true,
		},
		{
			name:         "v6 path",
			serverSubdir: "v6",
		},
		{
			name:         "root path",
			serverSubdir: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(-24 * time.Hour))
			if !test.useDefault {
				srv.ServerSubdir = test.serverSubdir
			}

			url := srv.Start() // one day ago
			parts := strings.Split(url, "/")
			urlPrefix := strings.Join(parts[:len(parts)-1], "/")

			get := func(url string) (status int, contents []byte, readError error) {
				resp, err := http.Get(url)
				if resp.Body != nil {
					defer func() { require.NoError(t, resp.Body.Close()) }()
				}
				require.NoError(t, err)
				buf := bytes.Buffer{}
				_, err = io.Copy(&buf, resp.Body)
				return resp.StatusCode, buf.Bytes(), err
			}

			status, content, err := get(urlPrefix + "/latest.json")
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)

			// should have a latest document at the given URL
			var latest distribution.LatestDocument
			require.NoError(t, json.Unmarshal(content, &latest))

			relativeDb := latest.Archive.Path
			require.NotEmpty(t, relativeDb)

			// should have a db at the relative url in the latest doc
			status, content, err = get(urlPrefix + "/" + relativeDb)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, status)
			require.NotEmpty(t, content)

			// should have 404 at wrong URL
			status, _, _ = get(urlPrefix + "/asdf")
			require.Equal(t, http.StatusNotFound, status)
		})
	}
}
