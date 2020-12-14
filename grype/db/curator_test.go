package db

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/wagoodman/go-progress"

	"github.com/anchore/grype-db/pkg/curation"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/file"
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

func newTestCurator(fs afero.Fs, getter file.Getter, dbDir, metadataUrl string, validateDbHash bool) Curator {
	c := NewCurator(Config{
		DbDir:               dbDir,
		ListingURL:          metadataUrl,
		ValidateByHashOnGet: validateDbHash,
	})

	c.downloader = getter
	c.fs = fs
	return c
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
			cur := newTestCurator(fs, getter, "/tmp/dbdir", metadataUrl, false)

			path, err := cur.download(test.entry, &progress.Manual{})

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
			cur := newTestCurator(fs, getter, "/tmp/dbdir", metadataUrl, test.cfgValidateDbHash)

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
