package v6

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
)

const (
	// We follow SchemaVer semantics (see https://snowplow.io/blog/introducing-schemaver-for-semantic-versioning-of-schemas)

	// ModelVersion indicates how many breaking schema changes there have been (which will prevent interaction with any historical data)
	// note: this must ALWAYS be "6" in the context of this package.
	ModelVersion = 6

	// Revision indicates how many changes have been introduced which **may** prevent interaction with some historical data
	Revision = 1

	// Addition indicates how many changes have been introduced that are compatible with all historical data
	Addition = 8

	// v6 model changelog:
	// 6.0.0: Initial version 🎉
	// 6.0.1: Add CISA KEV to VulnerabilityDecorator store
	// 6.0.2: Add EPSS to VulnerabilityDecorator store
	// 6.0.3: Add channel column to OperatingSystem model
	// 6.1.0: Add Fix availability information to AffectedPackageBlob.Range.Fix.Detail.
	//        Existing git commit and timestamp information was removed (as it was unused)
	// 6.1.1: Add UnaffectedCPE / UnaffectedPackage models and stores (remove "Affected" prefixes from existing blobs)
	// 6.1.2: Add CWEs
	// 6.1.3: Add ID field to Reference (for advisory IDs like RHSA-2023:5455)
	// 6.1.4: Add EOLDate and EOASDate fields to OperatingSystem model
	// 6.1.5: Add RpmArch field to PackageQualifiers (used by the CSAF VEX transformer to tag
	//        source vs. binary RPM entries; the RPM matcher's upstream-search path filters
	//        out non-source entries so binary-granular advisories don't FP-match siblings)
	// 6.1.6: Add RootIO field to PackageQualifiers (used by the OSV rootio strategy to mark
	//        vulnerabilities that only apply to Root IO-backported packages; the rootio
	//        runtime qualifier in pkg/qualifier/rootio filters non-Root-IO packages out via
	//        the NAK pattern)
	// 6.1.7: Rename PackageQualifiers.RpmArch (json: rpm_arch) to Architecture (json:
	//        architecture). The field's semantics are unchanged; the rename drops the rpm-
	//        specific prefix because the value already lives in PackageQualifiers and can
	//        carry any architecture string for future arch-scoped advisories.
	// 6.1.8: Add ArchitectureAlias table (architecture_aliases). The architecture qualifier
	//        reads it at match time to fold dialect arch spellings (e.g. "x86_64" <-> "amd64")
	//        onto a canonical token. Older clients ignore the table; clients reading a DB built
	//        before it existed fall back to the built-in default aliases.
	// 6.1.9: Add GoImports field to PackageQualifiers (used by the govulndb OSV strategy to
	//        carry per-symbol matching from ecosystem_specific.imports; the gosymbols
	//        runtime qualifier in pkg/qualifier/gosymbols matches captured Go binary symbols
	//        so stdlib and golang.org/x/* advisories don't FP-match binaries that don't use
	//        vulnerable symbols)
)

const (
	VulnerabilityDBFileName = "vulnerability.db"

	// batchSize affects how many records are fetched at a time from the DB. Note: when using preload, row entries
	// for related records may convey as parameters in a "WHERE x in (...)" which can lead to a large number of
	// parameters in the query -- if above 999 then this will result in an error for sqlite. For this reason we
	// try to keep this value well below 999.
	batchSize = 300
)

var ErrDBCapabilityNotSupported = fmt.Errorf("capability not supported by DB")

type ReadWriter interface {
	Reader
	Writer
}

type Reader interface {
	DBMetadataStoreReader
	ProviderStoreReader
	VulnerabilityStoreReader
	VulnerabilityDecoratorStoreReader
	OperatingSystemStoreReader
	AffectedPackageStoreReader
	UnaffectedPackageStoreReader
	AffectedCPEStoreReader
	UnaffectedCPEStoreReader
	ArchitectureAliasStoreReader
	io.Closer
	attachBlobValue(...blobable) error
}

type Writer interface {
	DBMetadataStoreWriter
	ProviderStoreWriter
	VulnerabilityStoreWriter
	VulnerabilityDecoratorStoreWriter
	OperatingSystemStoreWriter
	AffectedPackageStoreWriter
	UnaffectedPackageStoreWriter
	AffectedCPEStoreWriter
	UnaffectedCPEStoreWriter
	io.Closer
}

type Curator interface {
	Reader() (Reader, error)
	Status() vulnerability.ProviderStatus
	Delete() error
	Update() (bool, error)
	Import(dbArchivePath string) error
}

type Config struct {
	DBDirPath string
	Debug     bool
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
		s, err := newStore(Config{DBDirPath: path}, false, true)
		if s != nil {
			log.CloseAndLogError(s, path)
		}
		return err
	}
}

// NewLowLevelDB creates a new empty DB for writing or opens an existing one for reading from the given path. This is
// not recommended for typical interactions with the vulnerability DB, use NewReader and NewWriter instead.
func NewLowLevelDB(dbFilePath string, empty, writable, debug bool) (*gorm.DB, error) {
	opts := []gormadapter.Option{
		gormadapter.WithDebug(debug),
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

	dbObj, err := gormadapter.Open(dbFilePath, opts...)
	if err != nil {
		return nil, err
	}

	if empty {
		// speed up writes by persisting key-to-ID lookups when writing to the DB
		dbObj = dbObj.WithContext(withCacheContext(context.Background(), newCache()))
	}

	return dbObj, err
}
