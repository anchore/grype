package distribution

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/stretchr/testify/mock"
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

func newTestCurator(tb testing.TB, fs afero.Fs, getter file.Getter, dbDir, metadataUrl string, validateDbHash bool) Curator {
	c, err := NewCurator(Config{
		DBRootDir:           dbDir,
		ListingURL:          metadataUrl,
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

	t.Log(color.Bold.Sprint("Generating Key/Cert Fixture"))

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

func Test_requireUpdateCheck(t *testing.T) {
	toJson := func(listing any) []byte {
		listingContents := bytes.Buffer{}
		enc := json.NewEncoder(&listingContents)
		_ = enc.Encode(listing)
		return listingContents.Bytes()
	}
	checksum := func(b []byte) string {
		h := sha256.New()
		h.Write(b)
		return hex.EncodeToString(h.Sum(nil))
	}
	makeTarGz := func(mod time.Time, contents []byte) []byte {
		metadata := toJson(MetadataJSON{
			Built:    mod.Format(time.RFC3339),
			Version:  5,
			Checksum: "sha256:" + checksum(contents),
		})
		tgz := bytes.Buffer{}
		gz := gzip.NewWriter(&tgz)
		w := tar.NewWriter(gz)
		_ = w.WriteHeader(&tar.Header{
			Name: "metadata.json",
			Size: int64(len(metadata)),
			Mode: 0600,
		})
		_, _ = w.Write(metadata)
		_ = w.WriteHeader(&tar.Header{
			Name: "vulnerability.db",
			Size: int64(len(contents)),
			Mode: 0600,
		})
		_, _ = w.Write(contents)
		_ = w.Close()
		_ = gz.Close()
		return tgz.Bytes()
	}

	newTime := time.Date(2024, 06, 13, 17, 13, 13, 0, time.UTC)
	midTime := time.Date(2022, 06, 13, 17, 13, 13, 0, time.UTC)
	oldTime := time.Date(2020, 06, 13, 17, 13, 13, 0, time.UTC)

	newDB := makeTarGz(newTime, []byte("some-good-contents"))

	midMetadata := toJson(MetadataJSON{
		Built:    midTime.Format(time.RFC3339),
		Version:  5,
		Checksum: "sha256:deadbeefcafe",
	})

	var handlerFunc http.HandlerFunc

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerFunc(w, r)
	}))
	defer srv.Close()

	newDbURI := "/db.tar.gz"

	newListing := toJson(Listing{Available: map[int][]ListingEntry{5: {ListingEntry{
		Built:    newTime,
		URL:      mustUrl(url.Parse(srv.URL + newDbURI)),
		Checksum: "sha256:" + checksum(newDB),
	}}}})

	oldListing := toJson(Listing{Available: map[int][]ListingEntry{5: {ListingEntry{
		Built:    oldTime,
		URL:      mustUrl(url.Parse(srv.URL + newDbURI)),
		Checksum: "sha256:" + checksum(newDB),
	}}}})

	newListingURI := "/listing.json"
	oldListingURI := "/oldlisting.json"
	badListingURI := "/badlisting.json"

	handlerFunc = func(response http.ResponseWriter, request *http.Request) {
		switch request.RequestURI {
		case newListingURI:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(newListing)
		case oldListingURI:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(oldListing)
		case newDbURI:
			response.WriteHeader(http.StatusOK)
			_, _ = response.Write(newDB)
		default:
			http.Error(response, "not found", http.StatusNotFound)
		}
	}

	tests := []struct {
		name       string
		config     Config
		dbDir      map[string][]byte
		wantResult bool
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name: "listing with update",
			config: Config{
				ListingURL:         srv.URL + newListingURI,
				RequireUpdateCheck: true,
			},
			dbDir: map[string][]byte{
				"5/metadata.json": midMetadata,
			},
			wantResult: true,
			wantErr:    require.NoError,
		},
		{
			name: "no update",
			config: Config{
				ListingURL:         srv.URL + oldListingURI,
				RequireUpdateCheck: false,
			},
			dbDir: map[string][]byte{
				"5/metadata.json": midMetadata,
			},
			wantResult: false,
			wantErr:    require.NoError,
		},
		{
			name: "update error fail",
			config: Config{
				ListingURL:         srv.URL + badListingURI,
				RequireUpdateCheck: true,
			},
			wantResult: false,
			wantErr:    require.Error,
		},
		{
			name: "update error continue",
			config: Config{
				ListingURL:         srv.URL + badListingURI,
				RequireUpdateCheck: false,
			},
			wantResult: false,
			wantErr:    require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbTmpDir := t.TempDir()
			tt.config.DBRootDir = dbTmpDir
			tt.config.ListingFileTimeout = 1 * time.Minute
			tt.config.UpdateTimeout = 1 * time.Minute
			for filePath, contents := range tt.dbDir {
				fullPath := filepath.Join(dbTmpDir, filepath.FromSlash(filePath))
				err := os.MkdirAll(filepath.Dir(fullPath), 0700|os.ModeDir)
				require.NoError(t, err)
				err = os.WriteFile(fullPath, contents, 0700)
				require.NoError(t, err)
			}
			c, err := NewCurator(tt.config)
			require.NoError(t, err)

			result, err := c.Update()
			require.Equal(t, tt.wantResult, result)
			tt.wantErr(t, err)
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

func TestCurator_IsUpdateCheckAllowed(t *testing.T) {
	fs := afero.NewOsFs()
	tempDir := t.TempDir()

	curator := Curator{
		fs:                      fs,
		updateCheckMaxFrequency: 10 * time.Minute,
		dbDir:                   tempDir,
	}

	writeLastCheckTime := func(t *testing.T, lastCheckTime time.Time) {
		err := afero.WriteFile(fs, path.Join(tempDir, lastUpdateCheckFileName), []byte(lastCheckTime.Format(time.RFC3339)), 0644)
		require.NoError(t, err)
	}

	t.Run("first run check (no last check file)", func(t *testing.T) {
		require.True(t, curator.isUpdateCheckAllowed())
	})

	t.Run("check not allowed due to frequency", func(t *testing.T) {
		writeLastCheckTime(t, time.Now().Add(-5*time.Minute))

		require.False(t, curator.isUpdateCheckAllowed())
	})

	t.Run("check allowed after the frequency period", func(t *testing.T) {
		writeLastCheckTime(t, time.Now().Add(-20*time.Minute))

		require.True(t, curator.isUpdateCheckAllowed())
	})
}

func TestCurator_DurationSinceUpdateCheck(t *testing.T) {
	fs := afero.NewOsFs()
	tempDir := t.TempDir()

	curator := Curator{
		fs:    fs,
		dbDir: tempDir,
	}

	writeLastCheckTime := func(t *testing.T, lastCheckTime time.Time) {
		err := afero.WriteFile(fs, path.Join(tempDir, lastUpdateCheckFileName), []byte(lastCheckTime.Format(time.RFC3339)), 0644)
		require.NoError(t, err)
	}

	t.Run("no last check file", func(t *testing.T) {
		elapsed, err := curator.durationSinceUpdateCheck()
		require.NoError(t, err)
		require.Nil(t, elapsed)
	})

	t.Run("last check file does not exist", func(t *testing.T) {
		// simulate a non-existing file
		_, err := curator.durationSinceUpdateCheck()
		require.NoError(t, err)
	})

	t.Run("valid last check file", func(t *testing.T) {
		writeLastCheckTime(t, time.Now().Add(-5*time.Minute))

		elapsed, err := curator.durationSinceUpdateCheck()
		require.NoError(t, err)
		require.NotNil(t, elapsed)
		require.True(t, *elapsed >= 5*time.Minute)
	})

	t.Run("malformed last check file", func(t *testing.T) {
		err := afero.WriteFile(fs, path.Join(tempDir, lastUpdateCheckFileName), []byte("not a timestamp"), 0644)
		require.NoError(t, err)

		_, err = curator.durationSinceUpdateCheck()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to parse last update check timestamp")
	})
}

func TestCurator_SetLastSuccessfulUpdateCheck(t *testing.T) {
	fs := afero.NewOsFs()
	tempDir := t.TempDir()

	curator := Curator{
		fs:    fs,
		dbDir: tempDir,
	}

	t.Run("set last successful update check", func(t *testing.T) {
		curator.setLastSuccessfulUpdateCheck()

		data, err := afero.ReadFile(fs, path.Join(tempDir, lastUpdateCheckFileName))
		require.NoError(t, err)

		lastCheckTime, err := time.Parse(time.RFC3339, string(data))
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().UTC(), lastCheckTime, time.Second)
	})

	t.Run("error writing last successful update check", func(t *testing.T) {
		invalidFs := afero.NewReadOnlyFs(fs) // make it read-only, which should simular a write error
		curator.fs = invalidFs

		curator.setLastSuccessfulUpdateCheck()
	})
}

// Mock for the file.Getter interface
type MockGetter struct {
	mock.Mock
}

func (m *MockGetter) GetFile(dst, src string, monitor ...*progress.Manual) error {
	args := m.Called(dst, src, monitor)
	return args.Error(0)
}

func (m *MockGetter) GetToDir(dst, src string, monitor ...*progress.Manual) error {
	args := m.Called(dst, src, monitor)
	return args.Error(0)
}

func TestCurator_Update_setLastSuccessfulUpdateCheck_notCalled(t *testing.T) {

	newCurator := func(t *testing.T) *Curator {
		return &Curator{
			fs:                      afero.NewOsFs(),
			dbDir:                   t.TempDir(),
			updateCheckMaxFrequency: 10 * time.Minute,
			listingDownloader:       &MockGetter{},
			updateDownloader:        &MockGetter{},
			requireUpdateCheck:      true,
		}
	}

	t.Run("error checking for update", func(t *testing.T) {
		c := newCurator(t)

		c.listingDownloader.(*MockGetter).On("GetFile", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("get listing failed"))

		_, err := c.Update()
		require.Error(t, err)
		require.ErrorContains(t, err, "get listing failed")

		require.NoFileExists(t, filepath.Join(t.TempDir(), lastUpdateCheckFileName))
	})

}
