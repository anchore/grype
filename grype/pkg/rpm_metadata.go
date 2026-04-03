package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ FileOwner = (*RpmMetadata)(nil)

type RpmMetadata struct {
	Epoch           *int            `json:"epoch" cyclonedx:"epoch"`
	ModularityLabel *string         `json:"modularityLabel" cyclonedx:"modularityLabel"`
	Files           []RpmFileRecord `json:"files"`
}

// RpmFileRecord represents a single file owned by an RPM package.
type RpmFileRecord struct {
	Path string `json:"path"`
}

func (m RpmMetadata) OwnedFiles() []string {
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
