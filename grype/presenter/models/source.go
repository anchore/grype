package models

import (
	"fmt"

	syftSource "github.com/anchore/syft/syft/source"
)

type source struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

// newSource creates a new source object to be represented into JSON.
func newSource(src syftSource.Description) (source, error) {
	switch m := src.Metadata.(type) {
	case syftSource.StereoscopeImageSourceMetadata:
		// ensure that empty collections are not shown as null
		if m.RepoDigests == nil {
			m.RepoDigests = []string{}
		}
		if m.Tags == nil {
			m.Tags = []string{}
		}

		return source{
			Type:   "image",
			Target: m,
		}, nil
	case syftSource.DirectorySourceMetadata:
		return source{
			Type:   "directory",
			Target: m.Path,
		}, nil
	case syftSource.FileSourceMetadata:
		return source{
			Type:   "file",
			Target: m.Path,
		}, nil
	case nil:
		// we may be showing results from a input source that does not support source information
		return source{
			Type:   "unknown",
			Target: "unknown",
		}, nil
	default:
		return source{}, fmt.Errorf("unsupported source: %T", src.Metadata)
	}
}
