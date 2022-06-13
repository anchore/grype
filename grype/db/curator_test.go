package db

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/gookit/color"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/file"
)

type testGetter struct {
	file  map[string]string
	dir   map[string]string
	calls internal.StringSet
	fs    afero.Fs
}

func newTestGetter(fs afero.Fs, f, d map[string]string) *testGetter {
	return &testGetter{
		file:  f,
		dir:   d,
		calls: internal.NewStringSet(),
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

	c.downloader = getter
	c.fs = fs

	return c
}

func Test_defaultHTTPClient(t *testing.T) {
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

			err := cur.validate(test.fixture)

			if err == nil && test.err {
				t.Errorf("expected an error but got none")
			} else if err != nil && !test.err {
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

func assertAs(expected string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorContains(t, err, expected)
	}
}

func TestCurator_validateStaleness(t *testing.T) {
	type fields struct {
		staleLimist time.Duration
		md          *Metadata
	}

	tests := []struct {
		name    string
		cur     *Curator
		fields  fields
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no-validation",
			fields: fields{
				md: &Metadata{Built: time.Now()},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "no-metadata",
			fields:  fields{},
			wantErr: assert.NoError,
		},
		{
			name: "up-to-date",
			fields: fields{
				staleLimist: time.Hour,
				md:          &Metadata{Built: time.Now()},
			},
			wantErr: assert.NoError,
		},
		{
			name: "stale-data",
			fields: fields{
				staleLimist: time.Hour,
				md:          &Metadata{Built: time.Now().Add(-3 * time.Hour)},
			},
			wantErr: assertAs("data is stale"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Curator{
				dataStalenessLimit: tt.fields.staleLimist,
			}
			tt.wantErr(t, c.validateStaleness(tt.fields.md), fmt.Sprintf("validateStaleness(%v)", tt.fields.md))
		})
	}
}
