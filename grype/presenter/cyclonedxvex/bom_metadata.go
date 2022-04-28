package cyclonedxvex

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/source"
)

// NewBomMetadata returns a new BomDescriptor tailored for the current time and "syft" tool details.
func NewBomMetadata(name, version string, srcMetadata *source.Metadata) *cyclonedx.Metadata {
	metadata := cyclonedx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cyclonedx.Tool{
			{
				Vendor:  "anchore",
				Name:    name,
				Version: version,
			},
		},
	}
	if srcMetadata != nil {
		switch srcMetadata.Scheme {
		case source.ImageScheme:
			metadata.Component = &cyclonedx.Component{
				Type:    "container",
				Name:    srcMetadata.ImageMetadata.UserInput,
				Version: srcMetadata.ImageMetadata.ManifestDigest,
			}
		case source.DirectoryScheme:
			metadata.Component = &cyclonedx.Component{
				Type: "file",
				Name: srcMetadata.Path,
			}
		}
	}
	return &metadata
}
