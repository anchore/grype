package v4

type Store interface {
	StoreReader
	StoreWriter
	DBCloser
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
}

type DiffReader interface {
	DiffStore(s StoreReader) (*[]Diff, error)
}

type DBCloser interface {
	Close()
}
