package file

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
	"github.com/xi2/xz"
)

// Note: this is a copy of the XzDecompressor from https://github.com/hashicorp/go-getter/blob/v2.2.3/decompress_xz.go
// with the xz lib swapped out (for performance). A few adjustments were made:
// - refactored to use afero filesystem abstraction
// - fixed some linting issues

// xzDecompressor is an implementation of Decompressor that can decompress xz files.
type xzDecompressor struct {
	// FileSizeLimit limits the size of a decompressed file.
	//
	// The zero value means no limit.
	FileSizeLimit int64

	Fs afero.Fs
}

func (d *xzDecompressor) Decompress(dst, src string, dir bool, umask os.FileMode) error {
	// Directory isn't supported at all
	if dir {
		return fmt.Errorf("xz-compressed files can only unarchive to a single file")
	}

	// If we're going into a directory we should make that first
	if err := d.Fs.MkdirAll(filepath.Dir(dst), mode(0755, umask)); err != nil {
		return err
	}

	// File first
	f, err := d.Fs.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	// xz compression is second
	xzR, err := xz.NewReader(f, 0)
	if err != nil {
		return err
	}

	// Copy it out, potentially using a file size limit.
	return copyReader(d.Fs, dst, xzR, 0622, umask, d.FileSizeLimit)
}

// copyReader copies from an io.Reader into a file, using umask to create the dst file
func copyReader(fs afero.Fs, dst string, src io.Reader, fmode, umask os.FileMode, fileSizeLimit int64) error {
	dstF, err := fs.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, fmode)
	if err != nil {
		return err
	}
	defer dstF.Close()

	if fileSizeLimit > 0 {
		src = io.LimitReader(src, fileSizeLimit)
	}

	_, err = io.Copy(dstF, src)
	if err != nil {
		return err
	}

	// Explicitly chmod; the process umask is unconditionally applied otherwise.
	// We'll mask the mode with our own umask, but that may be different than
	// the process umask
	return fs.Chmod(dst, mode(fmode, umask))
}

// mode returns the file mode masked by the umask
func mode(mode, umask os.FileMode) os.FileMode {
	return mode & ^umask
}
