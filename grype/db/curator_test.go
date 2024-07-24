package db

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gookit/color"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/internal/file"
	"github.com/anchore/grype/internal/stringutil"
)

type testGetter struct {
	file  map[string]string
	dir   map[string]string
	calls stringutil.StringSet
	fs    afero.Fs
}

func newTestGetter(fs afero.Fs, f, d map[string]string) *testGetter {
	return &testGetter{
		file:  f,
		dir:   d,
		calls: stringutil.NewStringSet(),
		fs:    fs,
	}
}

// GetFile downloads the give URL into the given path. The URL must reference a single file.
func (g *testGetter) GetFile(dst, src string, _ ...*progress.Manual) error {
	g.calls.Add(src)
	if _, ok := g.file[src]; !ok {
		return fmt.Errorf("blerg, no file!")
	}
	return afero.WriteFile(g.fs, dst, []byte(g.file[src]), 0755)
}

// Get downloads the given URL into the given directory. The directory must already exist.
func (g *testGetter) GetToDir(dst, src string, _ ...*progress.Manual) error {
	g.calls.Add(src)
	if _, ok := g.dir[src]; !ok {
		return fmt.Errorf("blerg, no file!")
	}
	return afero.WriteFile(g.fs, dst, []byte(g.dir[src]), 0755)
}

func newTestCurator(tb testing.TB, fs afero.Fs, getter file.Getter, dbDir, listingFileURL string, validateDbHash bool) Curator {
	c, err := NewCurator(Config{
		DBRootDir:           dbDir,
		ListingURL:          listingFileURL,
		ValidateByHashOnGet: validateDbHash,
	})

	require.NoError(tb, err)

	c.listingDownloader = getter
	c.updateDownloader = getter
	c.fs = fs

	return c
}

func Test_defaultHTTPClientHasCert(t *testing.T) {
	tests := []struct {
		name    string
		hasCert bool
	}{
		{
			name:    "no custom cert should use default system root certs",
			hasCert: false,
		},
		{
			name:    "should use single custom cert",
			hasCert: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var certPath string
			if test.hasCert {
				certPath = generateCertFixture(t)
			}

			httpClient, err := defaultHTTPClient(afero.NewOsFs(), certPath)
			require.NoError(t, err)

			if test.hasCert {
				require.NotNil(t, httpClient.Transport.(*http.Transport).TLSClientConfig)
				assert.Len(t, httpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs.Subjects(), 1)
			} else {
				assert.Nil(t, httpClient.Transport.(*http.Transport).TLSClientConfig)
			}
		})
	}
}

func Test_defaultHTTPClientTimeout(t *testing.T) {
	c, err := defaultHTTPClient(afero.NewMemMapFs(), "")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, c.Timeout)
}

func generateCertFixture(t *testing.T) string {
	path := "test-fixtures/tls/server.crt"
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		// fixture already exists...
		return path
	}

	t.Logf(color.Bold.Sprint("Generating Key/Cert Fixture"))

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("unable to get cwd: %+v", err)
	}

	cmd := exec.Command("make", "server.crt")
	cmd.Dir = filepath.Join(cwd, "test-fixtures/tls")

	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("could not get stderr: %+v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("could not get stdout: %+v", err)
	}

	err = cmd.Start()
	if err != nil {
		t.Fatalf("failed to start cmd: %+v", err)
	}

	show := func(label string, reader io.ReadCloser) {
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			t.Logf("%s: %s", label, scanner.Text())
		}
	}
	go show("out", stdout)
	go show("err", stderr)

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0

			// This works on both Unix and Windows. Although package
			// syscall is generally platform dependent, WaitStatus is
			// defined for both Unix and Windows and in both cases has
			// an ExitStatus() method with the same signature.
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				if status.ExitStatus() != 0 {
					t.Fatalf("failed to generate fixture: rc=%d", status.ExitStatus())
				}
			}
		} else {
			t.Fatalf("unable to get generate fixture result: %+v", err)
		}
	}
	return path
}

func TestCuratorDownload(t *testing.T) {
	tests := []struct {
		name        string
		entry       *ListingEntry
		expectedURL string
		err         bool
	}{
		{
			name: "download populates returned tempdir",
			entry: &ListingEntry{
				Built:    time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC),
				URL:      mustUrl(url.Parse("http://a-url/payload.tar.gz")),
				Checksum: "sha256:deadbeefcafe",
			},
			expectedURL: "http://a-url/payload.tar.gz?checksum=sha256%3Adeadbeefcafe",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadataUrl := "http://metadata.io"
			contents := "CONTENTS!!!"
			files := map[string]string{}
			dirs := map[string]string{
				test.expectedURL: contents,
			}
			fs := afero.NewMemMapFs()
			getter := newTestGetter(fs, files, dirs)
			cur := newTestCurator(t, fs, getter, "/tmp/dbdir", metadataUrl, false)

			path, err := cur.download(test.entry, &progress.Manual{})
			if err != nil {
				t.Fatalf("could not download entry: %+v", err)
			}

			if !getter.calls.Contains(test.expectedURL) {
				t.Fatalf("never made the appropriate fetch call: %+v", getter.calls)
			}

			f, err := fs.Open(path)
			if err != nil {
				t.Fatalf("no db file: %+v", err)
			}

			actual, err := afero.ReadAll(f)
			if err != nil {
				t.Fatalf("bad db file read: %+v", err)
			}

			if string(actual) != contents {
				t.Fatalf("bad contents: %+v", string(actual))
			}
		})
	}
}

func TestCuratorValidate(t *testing.T) {
	tests := []struct {
		name              string
		fixture           string
		constraint        int
		cfgValidateDbHash bool
		err               bool
	}{
		{
			name:              "good checksum & good constraint",
			fixture:           "test-fixtures/curator-validate/good-checksum",
			cfgValidateDbHash: true,
			constraint:        1,
			err:               false,
		},
		{
			name:              "good checksum & bad constraint",
			fixture:           "test-fixtures/curator-validate/good-checksum",
			cfgValidateDbHash: true,
			constraint:        2,
			err:               true,
		},
		{
			name:              "bad checksum & good constraint",
			fixture:           "test-fixtures/curator-validate/bad-checksum",
			cfgValidateDbHash: true,
			constraint:        1,
			err:               true,
		},
		{
			name:              "bad checksum & bad constraint",
			fixture:           "test-fixtures/curator-validate/bad-checksum",
			cfgValidateDbHash: true,
			constraint:        2,
			err:               true,
		},
		{
			name:              "bad checksum ignored on config exception",
			fixture:           "test-fixtures/curator-validate/bad-checksum",
			cfgValidateDbHash: false,
			constraint:        1,
			err:               false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadataUrl := "http://metadata.io"

			fs := afero.NewOsFs()
			getter := newTestGetter(fs, nil, nil)
			cur := newTestCurator(t, fs, getter, "/tmp/dbdir", metadataUrl, test.cfgValidateDbHash)

			cur.targetSchema = test.constraint

			md, err := cur.validateIntegrity(test.fixture)

			if err == nil && test.err {
				t.Errorf("expected an error but got none")
			} else if err != nil && !test.err {
				assert.NotZero(t, md)
				t.Errorf("expected no error, got: %+v", err)
			}
		})
	}
}

func TestCuratorDBPathHasSchemaVersion(t *testing.T) {
	fs := afero.NewMemMapFs()
	dbRootPath := "/tmp/dbdir"
	cur := newTestCurator(t, fs, nil, dbRootPath, "http://metadata.io", false)

	assert.Equal(t, path.Join(dbRootPath, strconv.Itoa(cur.targetSchema)), cur.dbDir, "unexpected dir")
	assert.Contains(t, cur.dbPath, path.Join(dbRootPath, strconv.Itoa(cur.targetSchema)), "unexpected path")
}

func TestCurator_validateStaleness(t *testing.T) {
	type fields struct {
		validateAge     bool
		maxAllowedDBAge time.Duration
		md              Metadata
	}

	now := time.Now().UTC()
	tests := []struct {
		name    string
		cur     *Curator
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no-validation",
			fields: fields{
				md: Metadata{Built: now},
			},
			wantErr: assert.NoError,
		},
		{
			name: "up-to-date",
			fields: fields{
				maxAllowedDBAge: 2 * time.Hour,
				validateAge:     true,
				md:              Metadata{Built: now},
			},
			wantErr: assert.NoError,
		},
		{
			name: "stale-data",
			fields: fields{
				maxAllowedDBAge: time.Hour,
				validateAge:     true,
				md:              Metadata{Built: now.UTC().Add(-4 * time.Hour)},
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "the vulnerability database was built")
			},
		},
		{
			name: "stale-data-no-validation",
			fields: fields{
				maxAllowedDBAge: time.Hour,
				validateAge:     false,
				md:              Metadata{Built: now.Add(-4 * time.Hour)},
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Curator{
				validateAge:        tt.fields.validateAge,
				maxAllowedBuiltAge: tt.fields.maxAllowedDBAge,
			}
			tt.wantErr(t, c.validateStaleness(tt.fields.md), fmt.Sprintf("validateStaleness(%v)", tt.fields.md))
		})
	}
}

func TestCuratorTimeoutBehavior(t *testing.T) {
	failAfter := 10 * time.Second
	success := make(chan struct{})
	errs := make(chan error)
	timeout := time.After(failAfter)

	hangForeverHandler := func(w http.ResponseWriter, r *http.Request) {
		select {} // hang forever
	}

	ts := httptest.NewServer(http.HandlerFunc(hangForeverHandler))

	cfg := Config{
		DBRootDir:           "",
		ListingURL:          fmt.Sprintf("%s/listing.json", ts.URL),
		CACert:              "",
		ValidateByHashOnGet: false,
		ValidateAge:         false,
		MaxAllowedBuiltAge:  0,
		ListingFileTimeout:  400 * time.Millisecond,
		UpdateTimeout:       400 * time.Millisecond,
	}

	curator, err := NewCurator(cfg)
	require.NoError(t, err)

	u, err := url.Parse(fmt.Sprintf("%s/some-db.tar.gz", ts.URL))
	require.NoError(t, err)

	entry := ListingEntry{
		Built:    time.Now(),
		Version:  5,
		URL:      u,
		Checksum: "83b52a2aa6aff35d208520f40dd36144",
	}

	downloadProgress := progress.NewManual(10)
	importProgress := progress.NewManual(10)
	stage := progress.NewAtomicStage("some-stage")

	runTheTest := func(success chan struct{}, errs chan error) {
		_, _, _, err = curator.IsUpdateAvailable()
		if err == nil {
			errs <- errors.New("expected timeout error but got nil")
			return
		}
		if !strings.Contains(err.Error(), "Timeout exceeded") {
			errs <- fmt.Errorf("expected %q but got %q", "Timeout exceeded", err.Error())
			return
		}

		err = curator.UpdateTo(&entry, downloadProgress, importProgress, stage)
		if err == nil {
			errs <- errors.New("expected timeout error but got nil")
			return
		}
		if !strings.Contains(err.Error(), "Timeout exceeded") {
			errs <- fmt.Errorf("expected %q but got %q", "Timeout exceeded", err.Error())
			return
		}
		success <- struct{}{}
	}
	go runTheTest(success, errs)

	select {
	case <-success:
		return
	case err := <-errs:
		t.Error(err)
	case <-timeout:
		t.Fatalf("timeout exceeded (%v)", failAfter)
	}
}

func TestCuratorIsUpdateAvailable(t *testing.T) {
	testDir := "/tmp/dbDir"
	listingURL := "http://example.com/metadata/listing.json"
	tests := []struct {
		name              string
		existingMetadata  Metadata
		listing           Listing
		forceListingCheck bool
		wantListingCheck  bool
		wantUpdate        bool
		wantErr           bool
	}{
		{
			name:             "skip update check; too soon",
			existingMetadata: metadataBuiltAt(time.Now().Add(-10 * time.Minute)),
			wantListingCheck: false,
			wantUpdate:       false,
			wantErr:          false,
		},
		{
			name:              "force causes check even if local metadata is very new",
			existingMetadata:  metadataBuiltAt(time.Now().Add(-10 * time.Minute)),
			listing:           listingWithEntryBuiltAt(time.Time{}, "http://example.com/payload.tar.gz"),
			forceListingCheck: true,
			wantListingCheck:  true,
			wantUpdate:        false,
			wantErr:           false,
		},
		{
			name:             "check for update but not needed",
			existingMetadata: metadataBuiltAt(time.Now().Add(-50 * time.Hour)), // old listing file
			listing:          listingWithEntryBuiltAt(time.Time{}, "http://example.com/payload.tar.gz"),
			wantListingCheck: true,
			wantUpdate:       false,
			wantErr:          false,
		},
		{
			name:             "update needed",
			wantListingCheck: true,
			wantUpdate:       true,
			wantErr:          false,
			existingMetadata: metadataBuiltAt(time.Now().Add(-50 * time.Hour)), // old listing file
			listing:          listingWithEntryBuiltAt(time.Now().Add(-1*time.Hour), "http://example.com/payload.tar.gz"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			b, err := json.Marshal(tt.listing)
			require.NoError(t, err)
			files[listingURL] = string(b)
			dirs := map[string]string{}
			fs := afero.NewMemMapFs()
			fs.MkdirAll(path.Join(testDir, "5"), 0755)
			f, err := fs.Create(path.Join(testDir, "5", "metadata.json"))
			require.NoError(t, err)
			defer f.Close()
			err = json.NewEncoder(f).Encode(tt.existingMetadata)
			require.NoError(t, err)
			getter := newTestGetter(fs, files, dirs)
			cur := newTestCurator(t, fs, getter, testDir, listingURL, false)
			cur.minBuildAgeToCheck = 12 * time.Hour
			if tt.forceListingCheck {
				cur.minBuildAgeToCheck = 0
			}
			gotUpdate, _, _, gotErr := cur.IsUpdateAvailable()
			if tt.wantErr {
				require.Error(t, gotErr)
				return
			}
			if !tt.wantListingCheck {
				assert.Empty(t, getter.calls)
			} else {
				assert.True(t, getter.calls.Contains(listingURL))
			}
			require.NoError(t, gotErr)
			assert.Equal(t, tt.wantUpdate, gotUpdate)
		})
	}
}

func metadataBuiltAt(t time.Time) Metadata {
	return Metadata{
		Built:    t,
		Version:  5,
		Checksum: "sha256:972d0f51e180d424f3fff2637a1559e06940f35eda6bd03593be2a3db8f28971",
	}
}

func listingWithEntryBuiltAt(t time.Time, u string) Listing {
	return Listing{Available: map[int][]ListingEntry{
		5: {
			ListingEntry{
				Built:    t,
				URL:      mustUrl(url.Parse(u)),
				Version:  5,
				Checksum: "sha256:0123456789abcdef",
			},
		},
	}}

}
