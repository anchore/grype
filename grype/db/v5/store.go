package v5

import "github.com/anchore/grype/grype/db/v5/purlvulnerability"

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
	// TODO: DATA OVERRIDES: ability to write new vuln types
	purlvulnerability.Writer
}

type DiffReader interface {
	DiffStore(s StoreReader) (*[]Diff, error)
}

type DBCloser interface {
	Close()
}
