package v4

type Store interface {
	StoreReader
	StoreWriter
}

type StoreReader interface {
	IDReader
	DiffReader
	VulnerabilityStoreReader
	VulnerabilityMetadataStoreReader
	VulnerabilityMatchExclusionStoreReader
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
	VulnerabilityMatchExclusionStoreWriter
	Close()
}

type DiffReader interface {
	DiffStore(s StoreReader) (*[]Diff, error)
}
