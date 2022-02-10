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
func newSource(src syftSource.Metadata) (source, error) {
	switch src.Scheme {
	case syftSource.ImageScheme:
		return source{
			Type:   "image",
			Target: src.ImageMetadata,
		}, nil
	case syftSource.DirectoryScheme:
		return source{
			Type:   "directory",
			Target: src.Path,
		}, nil
	case syftSource.FileScheme:
		return source{
			Type:   "file",
			Target: src.Path,
		}, nil
	case "":
		// we may be showing results from a input source that does not support source information
		return source{
			Type:   "unknown",
			Target: "unknown",
		}, nil
	default:
		return source{}, fmt.Errorf("unsupported source: %q", src.Scheme)
	}
}
