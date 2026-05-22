package tarutil

import (
	"fmt"
	"io"
	"os"
)

var _ Entry = (*FileEntry)(nil)

type FileEntry struct {
	Path string
}

func NewEntryFromFilePath(path string) Entry {
	return FileEntry{
		Path: path,
	}
}

func NewEntryFromFilePaths(paths ...string) []Entry {
	var entries []Entry
	for _, path := range paths {
		entries = append(entries, NewEntryFromFilePath(path))
	}
	return entries
}

func (t FileEntry) writeEntry(tw lowLevelWriter) error {
	fi, err := os.Lstat(t.Path)
	if err != nil {
		return fmt.Errorf("unable to stat file %q: %w", t.Path, err)
	}
	return writeEntry(tw, t.Path, fi, func() (io.Reader, error) {
		return os.Open(t.Path)
	})
}
