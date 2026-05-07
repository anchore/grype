package tarutil

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ lowLevelWriter = (*mockTarWriter)(nil)

var _ os.FileInfo = (*mockFileInfo)(nil)

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

func TestReaderEntry_writeEntry(t *testing.T) {
	d := t.TempDir()
	file := filepath.Join(d, "file.txt")
	require.NoError(t, os.WriteFile(file, []byte("hello world"), 0644))

	link := filepath.Join(d, "link")
	require.NoError(t, os.Symlink(file, link))

	dir := filepath.Join(d, "dir")
	require.NoError(t, os.Mkdir(dir, 0755))

	tests := []struct {
		name        string
		typeFlag    byte
		bytes       []byte
		filename    string
		fileinfo    os.FileInfo
		wantErr     require.ErrorAssertionFunc
		expectFlush bool
		fs          afero.Fs
	}{
		{
			name:        "valid file",
			typeFlag:    tar.TypeReg,
			bytes:       []byte("hello world"),
			filename:    file,
			expectFlush: true,
			fileinfo: &mockFileInfo{
				name:    file,
				size:    11,
				mode:    0644,
				modTime: time.Now(),
				isDir:   false,
				sys:     nil,
			},
		},
		{
			name:        "symlink",
			typeFlag:    tar.TypeSymlink,
			bytes:       nil,
			filename:    link,
			expectFlush: false,
			fileinfo: &mockFileInfo{
				name:    link,
				size:    0,
				mode:    os.ModeSymlink,
				modTime: time.Now(),
				isDir:   false,
			},
		},
		{
			name:        "directory",
			typeFlag:    tar.TypeDir,
			bytes:       nil,
			filename:    dir,
			expectFlush: false,
			fileinfo: &mockFileInfo{
				name:    dir,
				size:    0,
				mode:    os.ModeDir,
				modTime: time.Now(),
				isDir:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			fe := NewEntryFromBytes(tt.bytes, tt.filename, tt.fileinfo)
			tw := &mockTarWriter{}

			err := fe.writeEntry(tw)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			assert.NoError(t, err)
			require.Len(t, tw.headers, 1)
			assert.Equal(t, tt.typeFlag, tw.headers[0].Typeflag)
			assert.Equal(t, tt.filename, tw.headers[0].Name)
			assert.Equal(t, int64(len(tt.bytes)), tw.headers[0].Size)
			assert.Equal(t, string(tt.bytes), tw.buffers[0].String())
			assert.Equal(t, tt.expectFlush, tw.flushCalled)
		})
	}
}

func Test_readerWithSize(t *testing.T) {
	testData := "hello world from test"

	tests := []struct {
		name     string
		reader   func(t *testing.T) io.Reader
		wantSize int64
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "bytes.Reader",
			reader: func(t *testing.T) io.Reader {
				return bytes.NewReader([]byte(testData))
			},
			wantSize: int64(len(testData)),
		},
		{
			name: "os.File success",
			reader: func(t *testing.T) io.Reader {
				dir := t.TempDir()
				path := filepath.Join(dir, "test.txt")
				require.NoError(t, os.WriteFile(path, []byte(testData), 0644))
				f, err := os.Open(path)
				require.NoError(t, err)
				t.Cleanup(func() { f.Close() })
				return f
			},
			wantSize: int64(len(testData)),
		},
		{
			name: "os.File stat fails",
			reader: func(t *testing.T) io.Reader {
				dir := t.TempDir()
				path := filepath.Join(dir, "test.txt")
				require.NoError(t, os.WriteFile(path, []byte(testData), 0644))
				f, err := os.Open(path)
				require.NoError(t, err)
				f.Close()
				return f
			},
			wantErr: require.Error,
		},
		{
			name: "unknown reader creates temp file",
			reader: func(t *testing.T) io.Reader {
				return strings.NewReader(testData)
			},
			wantSize: int64(len(testData)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			reader := tt.reader(t)
			size, rc, err := readerWithSize(reader)
			tt.wantErr(t, err)
			if err != nil {
				return
			}
			defer rc.Close()

			assert.Equal(t, tt.wantSize, size)

			content, err := io.ReadAll(rc)
			require.NoError(t, err)
			assert.Equal(t, testData, string(content))
		})
	}
}

func Test_autoDeleteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(path, []byte("test content"), 0644))

	f, err := os.Open(path)
	require.NoError(t, err)

	adf := &autoDeleteFile{File: f}

	_, err = os.Stat(path)
	require.NoError(t, err)

	err = adf.Close()
	require.NoError(t, err)

	_, err = os.Stat(path)
	assert.True(t, os.IsNotExist(err))
}
