package db

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/anchore/go-version"
	"github.com/anchore/vulnscan-db/pkg/db/curation"
	"github.com/anchore/vulnscan/internal"
	"github.com/anchore/vulnscan/internal/file"
	"github.com/spf13/afero"
)

func mustUrl(u *url.URL, err error) *url.URL {
	if err != nil {
		panic(err)
	}
	return u
}

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
func (g *testGetter) GetFile(dst, src string) error {
	g.calls.Add(src)
	if _, ok := g.file[src]; !ok {
		return fmt.Errorf("blerg, no file!")
	}
	return afero.WriteFile(g.fs, dst, []byte(g.file[src]), 0755)
}

// Get downloads the given URL into the given directory. The directory must already exist.
func (g *testGetter) GetToDir(dst, src string) error {
	g.calls.Add(src)
	if _, ok := g.dir[src]; !ok {
		return fmt.Errorf("blerg, no file!")
	}
	return afero.WriteFile(g.fs, dst, []byte(g.dir[src]), 0755)
}

func newTestCurator(fs afero.Fs, getter file.Getter, dbDir, metadataUrl string) (Curator, error) {
	c, err := NewCurator(Config{
		DbDir:      dbDir,
		ListingURL: metadataUrl,
	})

	c.client = getter
	c.fs = fs
	return c, err
}

func TestCuratorDownload(t *testing.T) {
	tests := []struct {
		name        string
		entry       *curation.ListingEntry
		expectedURL string
		err         bool
	}{
		{
			name: "download populates returned tempdir",
			entry: &curation.ListingEntry{
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
			cur, err := newTestCurator(fs, getter, "/tmp/dbdir", metadataUrl)
			if err != nil {
				t.Fatalf("failed making curator: %+v", err)
			}

			path, err := cur.download(test.entry)

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
		name       string
		fixture    string
		constraint string
		err        bool
	}{
		{
			name:       "good checksum & good constraint",
			fixture:    "test-fixtures/curator-validate/good-checksum",
			constraint: ">=1.0.0, <2.0.0",
			err:        false,
		},
		{
			name:       "good checksum & bad constraint",
			fixture:    "test-fixtures/curator-validate/good-checksum",
			constraint: ">=0.0.0, <1.0.0",
			err:        true,
		},
		{
			name:       "bad checksum & good constraint",
			fixture:    "test-fixtures/curator-validate/bad-checksum",
			constraint: ">=1.0.0, <2.0.0",
			err:        true,
		},
		{
			name:       "bad checksum & bad constraint",
			fixture:    "test-fixtures/curator-validate/bad-checksum",
			constraint: ">=0.0.0, <1.0.0",
			err:        true,
		},
		{
			name:       "allow equal version",
			fixture:    "test-fixtures/curator-validate/good-checksum",
			constraint: ">=1.1.0",
			err:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadataUrl := "http://metadata.io"

			fs := afero.NewOsFs()
			getter := newTestGetter(fs, nil, nil)
			cur, err := newTestCurator(fs, getter, "/tmp/dbdir", metadataUrl)
			if err != nil {
				t.Fatalf("failed making curator: %+v", err)
			}

			constraint, err := version.NewConstraint(test.constraint)
			if err != nil {
				t.Errorf("unable to set DB curator version constraint (%s): %w", test.constraint, err)
			}
			cur.versionConstraint = constraint

			err = cur.validate(test.fixture)

			if err == nil && test.err {
				t.Errorf("expected an error but got none")
			} else if err != nil && !test.err {
				t.Errorf("expected no error, got: %+v", err)
			}
		})
	}
}
