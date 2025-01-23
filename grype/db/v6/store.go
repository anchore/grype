package v6

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type store struct {
	*dbMetadataStore
	*providerStore
	*vulnerabilityStore
	*affectedPackageStore
	*affectedCPEStore
	blobStore *blobStore
	db        *gorm.DB
	config    Config
	readOnly  bool
}

func InitialData() []any {
	var data []any
	os := KnownOperatingSystemSpecifierOverrides()
	for i := range os {
		data = append(data, &os[i])
	}

	p := KnownPackageSpecifierOverrides()
	for i := range p {
		data = append(data, &p[i])
	}
	return data
}

func newStore(cfg Config, empty, writable bool) (*store, error) {
	var path string
	if cfg.DBDirPath != "" {
		path = cfg.DBFilePath()
	}

	db, err := NewLowLevelDB(path, empty, writable)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	bs := newBlobStore(db)
	return &store{
		dbMetadataStore:      newDBMetadataStore(db),
		providerStore:        newProviderStore(db),
		vulnerabilityStore:   newVulnerabilityStore(db, bs),
		affectedPackageStore: newAffectedPackageStore(db, bs),
		affectedCPEStore:     newAffectedCPEStore(db, bs),
		blobStore:            bs,
		db:                   db,
		config:               cfg,
		readOnly:             !empty && !writable,
	}, nil
}

// Close closes the store and finalizes the blobs when the DB is open for writing. If open for reading, it does nothing.
func (s *store) Close() error {
	log.Debug("closing store")
	if s.readOnly {
		return nil
	}

	// drop all indexes, which saves a lot of space distribution-wise (these get re-created on running gorm auto-migrate)
	if err := dropAllIndexes(s.db); err != nil {
		return err
	}

	// compact the DB size
	log.Debug("vacuuming database")
	if err := s.db.Exec("VACUUM").Error; err != nil {
		return fmt.Errorf("failed to vacuum: %w", err)
	}

	// since we are using riskier statements to optimize write speeds, do a last integrity check
	log.Debug("running integrity check")
	if err := s.db.Exec("PRAGMA integrity_check").Error; err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	return nil
}

func dropAllIndexes(db *gorm.DB) error {
	tables, err := db.Migrator().GetTables()
	if err != nil {
		return fmt.Errorf("failed to get tables: %w", err)
	}

	log.WithFields("tables", len(tables)).Debug("discovering indexes")

	for _, table := range tables {
		indexes, err := db.Migrator().GetIndexes(table)
		if err != nil {
			return fmt.Errorf("failed to get indexes for table %s: %w", table, err)
		}

		log.WithFields("table", table, "indexes", len(indexes)).Trace("dropping indexes")
		for _, index := range indexes {
			// skip auto-generated UNIQUE or PRIMARY KEY indexes (sqlite will not allow you to drop these without more major surgery)
			if strings.HasPrefix(index.Name(), "sqlite_autoindex") {
				log.WithFields("table", table, "index", index.Name()).Trace("skip dropping autoindex")
				continue
			}
			log.WithFields("table", table, "index", index.Name()).Trace("dropping index")
			if err := db.Migrator().DropIndex(table, index.Name()); err != nil {
				return fmt.Errorf("failed to drop index %s on table %s: %w", index, table, err)
			}
		}
	}

	return nil
}
