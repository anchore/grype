package db

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"testing"
	"time"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/data/provider"
	"github.com/anchore/grype/internal/tarutil"
)

func Test_archiveProvider(t *testing.T) {
	type args struct {
		cfg  CacheBackupConfig
		root string
		name string
	}
	tests := []struct {
		name           string
		args           args
		wantNames      *strset.Set
		wantStateStale bool
		wantErr        require.ErrorAssertionFunc
	}{
		{
			name: "default config includes input",
			args: args{
				cfg: CacheBackupConfig{
					ResultsOnly: false,
				},
				root: "test-fixtures/test-root",
				name: "test-provider",
			},
			wantStateStale: false,
			wantNames: strset.New([]string{
				"test-provider/input/some-input-file.txt",
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			}...),
		},
		{
			name: "results only excludes input",
			args: args{
				cfg: CacheBackupConfig{
					ResultsOnly: true,
				},
				root: "test-fixtures/test-root",
				name: "test-provider",
			},
			wantNames: strset.New(
				"test-provider/metadata.json",
				"test-provider/results/results.db",
			),
			wantStateStale: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			dir := t.TempDir()
			archivePath := path.Join(dir, "archive.tar")
			tw, err := tarutil.NewWriter(archivePath)
			require.NoError(t, err)

			tt.args.cfg.ProviderRoot = tt.args.root
			err = archiveProvider(tt.args.cfg, tt.args.name, tw)
			if tt.wantErr != nil {
				tt.wantErr(t, err)
				return
			}
			tt.wantErr(t, err)
			require.NoError(t, tw.Close())

			f, err := os.Open(archivePath)
			require.NoError(t, err)
			var state provider.State
			foundNames := strset.New()
			tr := tar.NewReader(f)
			for {
				next, nextErr := tr.Next()
				if errors.Is(nextErr, io.EOF) {
					break
				}
				require.NoError(t, nextErr)
				if next.Name == path.Join(tt.args.name, "metadata.json") {
					err = json.NewDecoder(tr).Decode(&state)
					require.NoError(t, err)
				}
				foundNames.Add(next.Name)
			}
			assert.Equalf(t, tt.wantStateStale, state.Stale, "state had wrong staleness")
			setDiff := strset.SymmetricDifference(tt.wantNames, foundNames)
			assert.True(t, setDiff.IsEmpty())
		})
	}
}

var _ tarutil.Writer = (*mockWriter)(nil)

type mockWriter struct {
	writtenEntries []tarutil.Entry
	closeCalled    bool
	closeErr       error
	writeErr       error
}

func (m *mockWriter) WriteEntry(entry tarutil.Entry) error {
	m.writtenEntries = append(m.writtenEntries, entry)
	return m.writeErr
}

func (m *mockWriter) Close() error {
	m.closeCalled = true
	return m.closeErr
}

type mockFileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	isDir   bool
	sys     any
}

func (m mockFileInfo) Name() string {
	return m.name
}

func (m mockFileInfo) Size() int64 {
	return m.size
}

func (m mockFileInfo) Mode() fs.FileMode {
	return m.mode
}

func (m mockFileInfo) ModTime() time.Time {
	return m.modTime
}

func (m mockFileInfo) IsDir() bool {
	return m.isDir
}

func (m mockFileInfo) Sys() any {
	return m.sys
}

func Test_common_visitPath_cases(t *testing.T) {

	type visitorConstructor func(w tarutil.Writer) pathVisitor

	fullConstructor := func(w tarutil.Writer) pathVisitor { return cacheFullWorkspaceVisitStrategy{writer: w} }
	resultsOnlyConstructor := func(w tarutil.Writer) pathVisitor {
		return cacheResultsOnlyWorkspaceVisitStrategy{
			writer:       w,
			providerName: "test-provider",
			metadataPath: "test-provider/metadata.json",
			inputPath:    "test-provider/input",
		}
	}

	constructors := map[string]visitorConstructor{
		"full":         fullConstructor,
		"results-only": resultsOnlyConstructor,
	}

	tests := []struct {
		name           string
		filePath       string
		fileInfo       fs.FileInfo
		fileErr        error
		writer         *mockWriter
		wantErr        require.ErrorAssertionFunc
		wantEntryCount int
	}{
		{
			name:           "errors write no entries",
			filePath:       "some-path",
			fileInfo:       nil,
			fileErr:        errors.New("some-error"),
			writer:         &mockWriter{},
			wantEntryCount: 0,
			wantErr:        require.Error,
		},
		{
			name:           "directories are skipped",
			filePath:       "some-path",
			fileInfo:       mockFileInfo{isDir: true},
			writer:         &mockWriter{},
			wantEntryCount: 0,
			wantErr:        require.NoError,
		},
	}
	for _, tt := range tests {
		for name, constructor := range constructors {
			t.Run(name, func(t *testing.T) {
				t.Run(tt.name, func(t *testing.T) {
					if tt.wantErr == nil {
						tt.wantErr = require.NoError
					}
					s := constructor(tt.writer)

					err := s.visitPath(tt.filePath, tt.fileInfo, tt.fileErr)
					tt.wantErr(t, err)
					assert.Equal(t, tt.wantEntryCount, len(tt.writer.writtenEntries))
				})
			})
		}
	}
}
