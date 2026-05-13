package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ FileOwner = (*ApkMetadata)(nil)

type ApkMetadata struct {
	Files []ApkFileRecord `json:"files"`
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	Path string `json:"path"`
}

func (m ApkMetadata) OwnedFiles() []string {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result := s.List()
	sort.Strings(result)
	return result
}
