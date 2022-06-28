package v3

type Store interface {
	StoreReader
	StoreWriter
}

type StoreReader interface {
	IDReader
	DiffReader
	VulnerabilityStoreReader
	VulnerabilityMetadataStoreReader
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
}

type DiffReader interface {
	DiffStore(s StoreReader) (*[]Diff, error)
}
