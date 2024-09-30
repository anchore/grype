package file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ulikunitz/xz"
)

func TestXzDecompressor_Decompress(t *testing.T) {
	content := "This is a test for xz decompression."

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createXZFromString(t, fs, content)
	dstFile := filepath.Join(tmpDir, "dst_file.txt")

	decompressor := &xzDecompressor{
		Fs: fs,
	}

	err := decompressor.Decompress(dstFile, srcFile, false, 0000)
	require.NoError(t, err)

	data, err := afero.ReadFile(fs, dstFile)
	require.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func TestXzDecompressor_FileSizeLimit(t *testing.T) {
	content := "This is a test for xz decompression with file size limit."

	fs := afero.NewMemMapFs()
	srcFile, tmpDir := createXZFromString(t, fs, content)
	dstFile := filepath.Join(tmpDir, "dst_file.txt")

	fileSizeLimit := int64(10)

	decompressor := &xzDecompressor{
		FileSizeLimit: fileSizeLimit,
		Fs:            fs,
	}

	err := decompressor.Decompress(dstFile, srcFile, false, 0000)
	require.NoError(t, err)

	data, err := afero.ReadFile(fs, dstFile)
	require.NoError(t, err)
	assert.Equal(t, content[:fileSizeLimit], string(data))
}

func TestCopyReader(t *testing.T) {
	content := "This is the content for testing copyReader."

	fs := afero.NewMemMapFs()

	tmpDir := t.TempDir()
	srcFile := filepath.Join(tmpDir, "src_file.txt")
	err := afero.WriteFile(fs, srcFile, []byte(content), 0644)
	require.NoError(t, err)

	srcF, err := fs.Open(srcFile)
	require.NoError(t, err)
	defer srcF.Close()

	dstFile := filepath.Join(tmpDir, "dst_file.txt")

	err = copyReader(fs, dstFile, srcF, 0644, 0000, 0)
	require.NoError(t, err)

	info, err := fs.Stat(dstFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())

	data, err := afero.ReadFile(fs, dstFile)
	assert.NoError(t, err)
	assert.Equal(t, content, string(data))
}

func createXZFromString(t *testing.T, fs afero.Fs, content string) (string, string) {
	t.Helper()

	tmpDir, err := afero.TempDir(fs, "", "xz_decompressor_test")
	require.NoError(t, err)
	srcFile := filepath.Join(tmpDir, "src_file.xz")

	f, err := fs.Create(srcFile)
	require.NoError(t, err)
	defer f.Close()

	xzW, err := xz.NewWriter(f)
	require.NoError(t, err)
	defer xzW.Close()

	_, err = xzW.Write([]byte(content))
	assert.NoError(t, err)

	return srcFile, tmpDir
}
