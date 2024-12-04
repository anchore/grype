package v5

import "io"

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
	io.Closer
}

type StoreWriter interface {
	IDWriter
	VulnerabilityStoreWriter
	VulnerabilityMetadataStoreWriter
	VulnerabilityMatchExclusionStoreWriter
	io.Closer
}

type DiffReader interface {
	DiffStore(s StoreReader) (*[]Diff, error)
}
