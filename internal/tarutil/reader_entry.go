package tarutil

import (
	"archive/tar"
	"bytes"
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

		contents, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		header.Size = int64(len(contents))

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if _, err := tw.Write(contents); err != nil {
			return err
		}

		// ensure proper alignment in the tar archive (padding with zeros)
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	return nil
}
