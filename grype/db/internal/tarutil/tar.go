package tarutil

import (
	"archive/tar"
	"io"
)

// Writer represents a facade for writing entries to a tar file.
type Writer interface {
	WriteEntry(Entry) error
	io.Closer
}

// lowLevelWriter abstracts the *tar.Writer from the standard library.
type lowLevelWriter interface {
	WriteHeader(*tar.Header) error
	Flush() error
	io.WriteCloser
}

// Entry represents an entry that can be written to a tar file via a tar.Writer from the standard library.
type Entry interface {
	writeEntry(writer lowLevelWriter) error
}
