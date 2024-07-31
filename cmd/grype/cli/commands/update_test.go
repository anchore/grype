package commands

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anchore/clio"
	hashiVersion "github.com/anchore/go-version"
	"github.com/anchore/grype/cmd/grype/internal"
)

func TestIsUpdateAvailable(t *testing.T) {
	tests := []struct {
		name          string
		buildVersion  string
		latestVersion string
		code          int
		isAvailable   bool
		newVersion    string
		err           bool
	}{
		{
			name:          "equal",
			buildVersion:  "1.0.0",
			latestVersion: "1.0.0",
			code:          200,
			isAvailable:   false,
			newVersion:    "",
			err:           false,
		},
		{
			name:          "hasUpdate",
			buildVersion:  "1.0.0",
			latestVersion: "1.2.0",
			code:          200,
			isAvailable:   true,
			newVersion:    "1.2.0",
			err:           false,
		},
		{
			name:          "aheadOfLatest",
			buildVersion:  "1.2.0",
			latestVersion: "1.0.0",
			code:          200,
			isAvailable:   false,
			newVersion:    "",
			err:           false,
		},
		{
			name:          "EmptyUpdate",
			buildVersion:  "1.0.0",
			latestVersion: "",
			code:          200,
			isAvailable:   false,
			newVersion:    "",
			err:           true,
		},
		{
			name:          "GarbageUpdate",
			buildVersion:  "1.0.0",
			latestVersion: "hdfjksdhfhkj",
			code:          200,
			isAvailable:   false,
			newVersion:    "",
			err:           true,
		},
		{
			name:          "BadUpdate",
			buildVersion:  "1.0.0",
			latestVersion: "1.0.",
			code:          500,
			isAvailable:   false,
			newVersion:    "",
			err:           true,
		},
		{
			name:          "NoBuildVersion",
			buildVersion:  internal.NotProvided,
			latestVersion: "1.0.0",
			code:          200,
			isAvailable:   false,
			newVersion:    "",
			err:           false,
		},
		{
			name:          "BadUpdateValidVersion",
			buildVersion:  "1.0.0",
			latestVersion: "2.0.0",
			code:          404,
			isAvailable:   false,
			newVersion:    "",
			err:           true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// setup mocks
			// local...
			version := test.buildVersion
			// remote...
			handler := http.NewServeMux()
			handler.HandleFunc(latestAppVersionURL.path, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.code)
				_, _ = w.Write([]byte(test.latestVersion))
			})
			mockSrv := httptest.NewServer(handler)
			latestAppVersionURL.host = mockSrv.URL
			defer mockSrv.Close()

			isAvailable, newVersion, err := isUpdateAvailable(clio.Identification{Version: version})
			if err != nil && !test.err {
				t.Fatalf("got error but expected none: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			}

			if newVersion != test.newVersion {
				t.Errorf("unexpected NEW version: %+v", newVersion)
			}

			if isAvailable != test.isAvailable {
				t.Errorf("unexpected result: %+v", isAvailable)
			}
		})
	}

}

func TestFetchLatestApplicationVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		code     int
		err      bool
		expected *hashiVersion.Version
	}{
		{
			name:     "gocase",
			response: "1.0.0",
			code:     200,
			expected: hashiVersion.Must(hashiVersion.NewVersion("1.0.0")),
		},
		{
			name:     "garbage",
			response: "garbage",
			code:     200,
			expected: nil,
			err:      true,
		},
		{
			name:     "http 500",
			response: "1.0.0",
			code:     500,
			expected: nil,
			err:      true,
		},
		{
			name:     "http 404",
			response: "1.0.0",
			code:     404,
			expected: nil,
			err:      true,
		},
		{
			name:     "empty",
			response: "",
			code:     200,
			expected: nil,
			err:      true,
		},
		{
			name:     "too long",
			response: "this is really long this is really long this is really long this is really long this is really long this is really long this is really long this is really long ",
			code:     200,
			expected: nil,
			err:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// setup mock
			handler := http.NewServeMux()
			handler.HandleFunc(latestAppVersionURL.path, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.code)
				_, _ = w.Write([]byte(test.response))
			})
			mockSrv := httptest.NewServer(handler)
			latestAppVersionURL.host = mockSrv.URL
			defer mockSrv.Close()

			actual, err := fetchLatestApplicationVersion(clio.Identification{})
			if err != nil && !test.err {
				t.Fatalf("got error but expected none: %+v", err)
			} else if err == nil && test.err {
				t.Fatalf("expected error but got none")
			}

			if err != nil {
				return
			}

			if actual.String() != test.expected.String() {
				t.Errorf("unexpected version: %+v", actual.String())
			}
		})
	}

}

func Test_UserAgent(t *testing.T) {
	got := ""

	// setup mock
	handler := http.NewServeMux()
	handler.HandleFunc(latestAppVersionURL.path, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.0.0"))
	})
	mockSrv := httptest.NewServer(handler)
	latestAppVersionURL.host = mockSrv.URL
	defer mockSrv.Close()

	fetchLatestApplicationVersion(clio.Identification{
		Name:    "the-app",
		Version: "v3.2.1",
	})

	if got != "the-app v3.2.1" {
		t.Errorf("expected User-Agent header to match, got: %v", got)
	}
}
