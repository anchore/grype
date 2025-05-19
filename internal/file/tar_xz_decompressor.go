package file

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/xi2/xz"
)

// Note: this is a copy of the TarXzDecompressor from https://github.com/hashicorp/go-getter/blob/v2.2.3/decompress_txz.go
// with the xz lib swapped out (for performance). A few adjustments were made:
// - refactored to use afero filesystem abstraction
// - fixed some linting issues

// TarXzDecompressor is an implementation of Decompressor that can
// decompress tar.xz files.
type tarXzDecompressor struct {
	// FileSizeLimit limits the total size of all
	// decompressed files.
	//
	// The zero value means no limit.
	FileSizeLimit int64

	// FilesLimit limits the number of files that are
	// allowed to be decompressed.
	//
	// The zero value means no limit.
	FilesLimit int

	Fs afero.Fs
}

func (d *tarXzDecompressor) Decompress(dst, src string, dir bool, umask os.FileMode) error {
	// If we're going into a directory we should make that first
	mkdir := dst
	if !dir {
		mkdir = filepath.Dir(dst)
	}
	if err := d.Fs.MkdirAll(mkdir, mode(0755, umask)); err != nil {
		return err
	}

	// File first
	f, err := d.Fs.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	// xz compression is second
	txzR, err := xz.NewReader(f, 0)
	if err != nil {
		return fmt.Errorf("error opening an xz reader for %s: %s", src, err)
	}

	return untar(d.Fs, txzR, dst, src, dir, umask, d.FileSizeLimit, d.FilesLimit)
}

// untar is a shared helper for untarring an archive. The reader should provide
// an uncompressed view of the tar archive.
func untar(fs afero.Fs, input io.Reader, dst, src string, dir bool, umask os.FileMode, fileSizeLimit int64, filesLimit int) error { // nolint:funlen,gocognit
	tarR := tar.NewReader(input)
	done := false
	dirHdrs := []*tar.Header{}
	now := time.Now()

	var (
		fileSize   int64
		filesCount int
	)

	for {
		if filesLimit > 0 {
			filesCount++
			if filesCount > filesLimit {
				return fmt.Errorf("tar archive contains too many files: %d > %d", filesCount, filesLimit)
			}
		}

		hdr, err := tarR.Next()
		if err == io.EOF {
			if !done {
				// Empty archive
				return fmt.Errorf("empty archive: %s", src)
			}

			break
		}
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeSymlink, tar.TypeLink:
			// to prevent any potential indirect traversal attacks
			continue
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			// don't unpack extended headers as files
			continue
		}

		path := dst
		if dir {
			// Disallow parent traversal
			if containsDotDot(hdr.Name) {
				return fmt.Errorf("entry contains '..': %s", hdr.Name)
			}

			path = filepath.Join(path, hdr.Name) // nolint:gosec // hdr.Name is checked above
		}

		fileInfo := hdr.FileInfo()

		fileSize += fileInfo.Size()

		if fileSizeLimit > 0 && fileSize > fileSizeLimit {
			return fmt.Errorf("tar archive larger than limit: %d", fileSizeLimit)
		}

		if fileInfo.IsDir() {
			if !dir {
				return fmt.Errorf("expected a single file: %s", src)
			}

			// A directory, just make the directory and continue unarchiving...
			if err := fs.MkdirAll(path, mode(0755, umask)); err != nil {
				return err
			}

			// Record the directory information so that we may set its attributes
			// after all files have been extracted
			dirHdrs = append(dirHdrs, hdr)

			continue
		}
		// There is no ordering guarantee that a file in a directory is
		// listed before the directory
		dstPath := filepath.Dir(path)

		// Check that the directory exists, otherwise create it
		if _, err := fs.Stat(dstPath); os.IsNotExist(err) {
			if err := fs.MkdirAll(dstPath, mode(0755, umask)); err != nil {
				return err
			}
		}

		// We have a file. If we already decoded, then it is an error
		if !dir && done {
			return fmt.Errorf("expected a single file, got multiple: %s", src)
		}

		// Mark that we're done so future in single file mode errors
		done = true

		// Size limit is tracked using the returned file info.
		err = copyReader(fs, path, tarR, hdr.FileInfo().Mode(), umask, 0)
		if err != nil {
			return err
		}

		// Set the access and modification time if valid, otherwise default to current time
		aTime := now
		mTime := now
		if hdr.AccessTime.Unix() > 0 {
			aTime = hdr.AccessTime
		}
		if hdr.ModTime.Unix() > 0 {
			mTime = hdr.ModTime
		}
		if err := fs.Chtimes(path, aTime, mTime); err != nil {
			return err
		}
	}

	// Perform a final pass over extracted directories to update metadata
	for _, dirHdr := range dirHdrs {
		path := filepath.Join(dst, dirHdr.Name) // nolint:gosec // hdr.Name is checked above
		// Chmod the directory since they might be created before we know the mode flags
		if err := fs.Chmod(path, mode(dirHdr.FileInfo().Mode(), umask)); err != nil {
			return err
		}
		// Set the mtime/atime attributes since they would have been changed during extraction
		aTime := now
		mTime := now
		if dirHdr.AccessTime.Unix() > 0 {
			aTime = dirHdr.AccessTime
		}
		if dirHdr.ModTime.Unix() > 0 {
			mTime = dirHdr.ModTime
		}
		if err := fs.Chtimes(path, aTime, mTime); err != nil {
			return err
		}
	}

	return nil
}

// containsDotDot checks if the filepath value v contains a ".." entry.
// This will check filepath components by splitting along / or \. This
// function is copied directly from the Go net/http implementation.
func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }
