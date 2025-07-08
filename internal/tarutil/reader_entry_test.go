package tarutil

import (
	"archive/tar"
	"io/fs"
	"os"
	"path/filepath"
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
