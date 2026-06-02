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

func TestPopulateWithPaths(t *testing.T) {
	tests := []struct {
		name    string
		tarPath string
		wantErr bool
	}{
		{
			name:    "plain tar",
			tarPath: "foo.tar",
			wantErr: false,
		},
		{
			name:    "tar gz",
			tarPath: "foo.tar.gz",
			wantErr: false,
		},
		{
			name:    "tar zst",
			tarPath: "foo.tar.zst",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tempPath := filepath.Join(dir, "some-path.txt")
			f, err := os.Create(tempPath)
			require.NoError(t, err)
			_, err = f.Write([]byte("hello world\n"))
			require.NoError(t, err)
			archivePath := filepath.Join(dir, tt.tarPath)
			err = PopulateWithPaths(archivePath, tempPath)
			require.NoError(t, err)

			var r io.Reader
			f, err = os.Open(archivePath)
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
			h, err := tr.Next()
			require.NoError(t, err)
			assert.Equal(t, h.Name, tempPath)
			b, err := io.ReadAll(tr)
			assert.Equal(t, []byte("hello world\n"), b)
		})
	}
}
