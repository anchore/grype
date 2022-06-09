package v4

type Store interface {
	StoreReader
	StoreWriter
}

type StoreReader interface {
	IDReader
	VulnerabilityStoreReader
	VulnerabilityMetadataStoreReader
	VulnerabilityMatchExclusionStoreReader
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
	VulnerabilityMatchExclusionStoreWriter
	Vacuum()
}
