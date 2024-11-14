package v6

import (
	"io"
	"path/filepath"
)

const (
	VulnerabilityDBFileName = "vulnerability.db"

	// We follow SchemaVer semantics (see https://snowplow.io/blog/introducing-schemaver-for-semantic-versioning-of-schemas)

	// ModelVersion indicates how many breaking schema changes there have been (which will prevent interaction with any historical data)
	// note: this must ALWAYS be "6" in the context of this package.
	ModelVersion = 6

	// Revision indicates how many changes have been introduced which **may** prevent interaction with some historical data
	Revision = 0

	// Addition indicates how many changes have been introduced that are compatible with all historical data
	Addition = 0
)

type ReadWriter interface {
	Reader
	Writer
}

type Reader interface {
	DBMetadataStoreReader
	ProviderStoreReader
	VulnerabilityStoreReader
	AffectedPackageStoreReader
	AffectedCPEStoreReader
}

type Writer interface {
	DBMetadataStoreWriter
	ProviderStoreWriter
	VulnerabilityStoreWriter
	AffectedPackageStoreWriter
	AffectedCPEStoreWriter
	io.Closer
}

type Config struct {
	DBDirPath string
}

func (c *Config) DBFilePath() string {
	return filepath.Join(c.DBDirPath, VulnerabilityDBFileName)
}

func NewReader(cfg Config) (Reader, error) {
	return newStore(cfg, false)
}

func NewWriter(cfg Config) (ReadWriter, error) {
	return newStore(cfg, true)
}
