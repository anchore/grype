package file

import (
	"archive/tar"
	"bytes"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func TestTarXzDecompressor_Decompress(t *testing.T) {
	files := map[string]string{
		"file1.txt": "This is file 1.",
		"file2.txt": "This is file 2.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.NoError(t, err)

	for name, content := range files {
		data, err := afero.ReadFile(fs, filepath.Join(dstDir, name))
		require.NoError(t, err)
		assert.Equal(t, content, string(data))
	}
}

func TestTarXzDecompressor_DecompressWithNestedDirs(t *testing.T) {
	files := map[string]string{
		"file1.txt":                "This is file 1.",
		"dir1/file2.txt":           "This is file 2 in dir1.",
		"dir1/dir2/file3.txt":      "This is file 3 in dir1/dir2.",
		"dir1/dir2/dir3/file4.txt": "This is file 4 in dir1/dir2/dir3.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.NoError(t, err)

	for name, content := range files {
		data, err := afero.ReadFile(fs, filepath.Join(dstDir, name))
		require.NoError(t, err)
		assert.Equal(t, content, string(data))
	}
}

func TestTarXzDecompressor_FileSizeLimit(t *testing.T) {
	files := map[string]string{
		"file1.txt": "This is file 1.",
		"file2.txt": "This is file 2.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		FileSizeLimit: int64(10), // setting a small file size limit
		Fs:            fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tar archive larger than limit")
}

func TestTarXzDecompressor_FilesLimit(t *testing.T) {
	files := map[string]string{
		"file1.txt": "This is file 1.",
		"file2.txt": "This is file 2.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		FilesLimit: 1, // setting a limit of 1 file
		Fs:         fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tar archive contains too many files")
}

func TestTarXzDecompressor_DecompressSingleFile(t *testing.T) {
	files := map[string]string{
		"file1.txt": "This is file 1.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstFile := filepath.Join(tmpDir, "single_file.txt")

	decompressor := &tarXzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstFile, srcFile, false, 0000)
	require.NoError(t, err)

	data, err := afero.ReadFile(fs, dstFile)
	require.NoError(t, err)
	assert.Equal(t, files["file1.txt"], string(data))
}

func TestTarXzDecompressor_EmptyArchive(t *testing.T) {
	files := map[string]string{}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty archive")
}

func TestTarXzDecompressor_PathTraversal(t *testing.T) {
	files := map[string]string{
		"../traversal_file.txt": "This file should not be extracted.",
	}

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createTarXzFromFiles(t, fs, files)
	dstDir := filepath.Join(tmpDir, "decompressed")

	decompressor := &tarXzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstDir, srcFile, true, 0000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entry contains '..'")
}

func createTarXzFromFiles(t *testing.T, fs afero.Fs, files map[string]string) (string, string) {
	t.Helper()

	tmpDir, err := afero.TempDir(fs, "", "tar_xz_decompressor_test")
	require.NoError(t, err)
	srcFile := filepath.Join(tmpDir, "src_file.tar.xz")

	var buf bytes.Buffer
	xzWriter, err := xz.NewWriter(&buf)
	require.NoError(t, err)

	tarWriter := tar.NewWriter(xzWriter)

	for name, content := range files {
		dir := filepath.Dir(name)
		if dir != "." {
			hdr := &tar.Header{
				Name:     dir + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
			}
			err := tarWriter.WriteHeader(hdr)
			require.NoError(t, err)
		}

		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		err := tarWriter.WriteHeader(hdr)
		require.NoError(t, err)

		_, err = tarWriter.Write([]byte(content))
		require.NoError(t, err)
	}

	err = tarWriter.Close()
	require.NoError(t, err)

	err = xzWriter.Close()
	require.NoError(t, err)

	err = afero.WriteFile(fs, srcFile, buf.Bytes(), 0644)
	require.NoError(t, err)

	return srcFile, tmpDir
}
