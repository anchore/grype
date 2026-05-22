package tarutil

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/anchore/grype/internal/log"
)

var _ Entry = (*ReaderEntry)(nil)

type ReaderEntry struct {
	Reader   io.Reader
	Filename string
	FileInfo os.FileInfo
}

func NewEntryFromBytes(by []byte, filename string, fileInfo os.FileInfo) Entry {
	return ReaderEntry{
		Reader:   bytes.NewReader(by),
		Filename: filename,
		FileInfo: fileInfo,
	}
}

func (t ReaderEntry) writeEntry(tw lowLevelWriter) error {
	log.WithFields("path", t.Filename).Trace("adding stream to archive")
	return writeEntry(tw, t.Filename, t.FileInfo, func() (io.Reader, error) {
		return t.Reader, nil
	})
}

// autoDeleteFile wraps an *os.File and deletes it when closed.
type autoDeleteFile struct {
	*os.File
}

func (f *autoDeleteFile) Close() error {
	name := f.Name()
	err := f.File.Close()
	if removeErr := os.Remove(name); removeErr != nil && err == nil {
		err = removeErr
	}
	return err
}

// readerWithSize determines the size of the reader's content without reading the entire content into memory.
// For known reader types (bytes.Reader, os.File), it queries the size directly.
// For unknown types, it copies to a temp file to avoid loading into memory.
// Returns the size, a ReadCloser for the content (may be different from input), and any error.
func readerWithSize(reader io.Reader) (int64, io.ReadCloser, error) {
	switch r := reader.(type) {
	case *bytes.Reader:
		// For bytes.Reader (used by NewEntryFromBytes), get actual size
		return r.Size(), io.NopCloser(reader), nil
	case interface{ Stat() (os.FileInfo, error) }:
		// For *os.File, use Stat to get size
		stat, err := r.Stat()
		if err != nil {
			return 0, nil, err
		}
		// Check if it's already a ReadCloser
		if rc, ok := reader.(io.ReadCloser); ok {
			return stat.Size(), rc, nil
		}
		return 0, nil, fmt.Errorf("reader with Stat() must implement io.ReadCloser")
	default:
		// Fallback for unknown reader types: copy to temp file to avoid loading into memory
		tmpFile, err := os.CreateTemp("", "grype-db-tar-*")
		if err != nil {
			return 0, nil, fmt.Errorf("unable to create temp file: %w", err)
		}

		size, err := io.Copy(tmpFile, reader)
		if err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return 0, nil, fmt.Errorf("unable to copy to temp file: %w", err)
		}

		// Seek back to beginning for reading
		if _, err := tmpFile.Seek(0, 0); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return 0, nil, fmt.Errorf("unable to seek temp file: %w", err)
		}

		return size, &autoDeleteFile{File: tmpFile}, nil
	}
}

func writeEntry(tw lowLevelWriter, filename string, fileInfo os.FileInfo, opener func() (io.Reader, error)) error {
	log.WithFields("path", filename).Trace("adding file to archive")

	header, err := tar.FileInfoHeader(fileInfo, "")
	if err != nil {
		return err
	}

	header.Name = filename
	switch fileInfo.Mode() & os.ModeType {
	case os.ModeDir:
		header.Size = 0
		err = tw.WriteHeader(header)
		if err != nil {
			return err
		}
		return nil

	case os.ModeSymlink:
		linkTarget, err := os.Readlink(filename)
		if err != nil {
			return err
		}
		header.Linkname = linkTarget
		header.Size = 0
		err = tw.WriteHeader(header)
		if err != nil {
			return err
		}
		return nil

	default:
		reader, err := opener()
		if err != nil {
			return err
		}

		size, readCloser, err := readerWithSize(reader)
		if err != nil {
			return err
		}
		defer readCloser.Close()

		header.Size = size

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Stream the file contents directly to the tar writer
		if _, err := io.Copy(tw, readCloser); err != nil {
			return err
		}

		// ensure proper alignment in the tar archive (padding with zeros)
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	return nil
}
