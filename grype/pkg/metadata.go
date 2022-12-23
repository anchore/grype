package pkg

// MetadataType represents the data shape stored within pkg.Package.Metadata.
type MetadataType string

const (
	// this is the full set of data shapes that can be represented within the pkg.Package.Metadata field

	UnknownMetadataType MetadataType = "UnknownMetadata"
	JavaMetadataType    MetadataType = "JavaMetadata"
	RpmMetadataType     MetadataType = "RpmMetadata"
	GolangMetadataType  MetadataType = "GolangMetadata"
)
