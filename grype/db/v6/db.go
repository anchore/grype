package v6

import (
	"fmt"
	"io"
	"path/filepath"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
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
	VulnerabilityStoreWriter
	AffectedPackageStoreWriter
	AffectedCPEStoreWriter
	io.Closer
}

type Curator interface {
	Reader() (Reader, error)
	Status() Status
	Delete() error
	Update() (bool, error)
	Import(dbArchivePath string) error
}

type Config struct {
	DBDirPath string
}

func (c Config) DBFilePath() string {
	return filepath.Join(c.DBDirPath, VulnerabilityDBFileName)
}

func NewReader(cfg Config) (Reader, error) {
	return newStore(cfg, false, false)
}

func NewWriter(cfg Config) (ReadWriter, error) {
	return newStore(cfg, true, true)
}

func Hydrater() func(string) error {
	return func(path string) error {
		// this will auto-migrate any models, creating and populating indexes as needed
		// we don't pass any data initialization here because the data is already in the db archive and we do not want
		// to affect the entries themselves, only indexes and schema.
		_, err := newStore(Config{DBDirPath: path}, false, true)
		return err
	}
}

// NewLowLevelDB creates a new empty DB for writing or opens an existing one for reading from the given path. This is
// not recommended for typical interactions with the vulnerability DB, use NewReader and NewWriter instead.
func NewLowLevelDB(dbFilePath string, empty, writable bool) (*gorm.DB, error) {
	opts := []gormadapter.Option{
		// 16 KB, useful for smaller DBs since ~85% of the DB is from the blobs table
		gormadapter.WithStatements("PRAGMA page_size = 16384"),
		// TODO: this should be removed after initial development (or wired to a config option)
		gormadapter.WithDebug(true),
	}

	if empty && !writable {
		return nil, fmt.Errorf("cannot open an empty database for reading only")
	}

	if empty {
		opts = append(opts,
			gormadapter.WithTruncate(true, Models(), InitialData()),
		)
	} else if writable {
		opts = append(opts, gormadapter.WithWritable(true, Models()))
	}

	return gormadapter.Open(dbFilePath, opts...)
}
