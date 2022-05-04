package v4

type Store interface {
	StoreReader
	StoreWriter
}

type StoreReader interface {
	IDReader
	VulnerabilityStoreReader
	VulnerabilityMetadataStoreReader
	VulnerabilityExclusionStoreReader
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
	VulnerabilityExclusionStoreWriter
}
