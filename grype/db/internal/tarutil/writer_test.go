package tarutil

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWriter(t *testing.T) {
	tests := []struct {
		name        string
		archivePath string
		wantErr     bool
	}{
		{
			name:        "tar.gz compressor",
			archivePath: "test.tar.gz",
			wantErr:     false,
		},
		{
			name:        "tar.zst compressor",
			archivePath: "test.tar.zst",
			wantErr:     false,
		},
		{
			name:        "tar compressor",
			archivePath: "test.tar",
			wantErr:     false,
		},
		{
			name:        "unsupported compressor",
			archivePath: "test.txt",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.Chdir(dir))
			testFilePath := "testfile"
			testString := "hello world"
			require.NoError(t, os.WriteFile(testFilePath, []byte(testString), 0644))

			archivePath := filepath.Join(dir, tt.archivePath)

			w, err := NewWriter(archivePath)
			if tt.wantErr {
				require.Error(t, err)
				return
			} else {
				require.NoError(t, err)
			}

			entry := NewEntryFromFilePath(testFilePath)

			err = w.WriteEntry(entry)
			require.NoError(t, err)

			err = w.Close()
			require.NoError(t, err)

			_, err = os.Stat(archivePath)
			assert.NoError(t, err)

			var r io.Reader
			f, err := os.Open(archivePath)
			require.NoError(t, err)
			defer f.Close()

			switch {
			case strings.HasSuffix(archivePath, ".tar.gz"):
				r, err = gzip.NewReader(f)
				require.NoError(t, err)
			case strings.HasSuffix(archivePath, ".tar.zst"):
				r, err = zstd.NewReader(f)
				require.NoError(t, err)
			case strings.HasSuffix(archivePath, ".tar"):
				r = f
			default:
				t.Fatalf("unsupported archive type: %s", archivePath)
			}

			tr := tar.NewReader(r)
			hdr, err := tr.Next()
			require.NoError(t, err)

			assert.Equal(t, testFilePath, hdr.Name)
			assert.Equal(t, int64(len(testString)), hdr.Size)

			content, err := io.ReadAll(tr)
			require.NoError(t, err)
			assert.Equal(t, testString, string(content))
		})
	}
}
