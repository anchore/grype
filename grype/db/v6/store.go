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
	*vulnerabilityDecoratorStore
	blobStore *blobStore
	db        *gorm.DB
	config    Config
	empty     bool
	writable  bool
}

func (s *store) getDB() *gorm.DB {
	return s.db
}

func (s *store) attachBlobValue(values ...blobable) error {
	return s.blobStore.attachBlobValue(values...)
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

	db, err := NewLowLevelDB(path, empty, writable, cfg.Debug)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	metadataStore := newDBMetadataStore(db)

	if empty {
		if err := metadataStore.SetDBMetadata(); err != nil {
			return nil, fmt.Errorf("failed to set db metadata: %w", err)
		}
	}

	meta, err := metadataStore.GetDBMetadata()
	if err != nil {
		return nil, fmt.Errorf("failed to get db metadata: %w", err)
	}

	if meta == nil {
		return nil, fmt.Errorf("no DB metadata found")
	}

	dbVersion := newSchemaVerFromDBMetadata(*meta)

	bs := newBlobStore(db)
	return &store{
		dbMetadataStore:             metadataStore,
		providerStore:               newProviderStore(db),
		vulnerabilityStore:          newVulnerabilityStore(db, bs),
		affectedPackageStore:        newAffectedPackageStore(db, bs),
		affectedCPEStore:            newAffectedCPEStore(db, bs),
		vulnerabilityDecoratorStore: newVulnerabilityDecoratorStore(db, bs, dbVersion),
		blobStore:                   bs,
		db:                          db,
		config:                      cfg,
		empty:                       empty,
		writable:                    writable,
	}, nil
}

// Close closes the store and finalizes the blobs when the DB is open for writing. If open for reading, only closes the connection to the DB.
func (s *store) Close() error {
	if !s.writable || !s.empty {
		d, err := s.db.DB()
		if err == nil {
			return d.Close()
		}
		// if not empty, this writable execution created indexes
		return nil
	}
	log.Debug("closing store")

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

	d, err := s.db.DB()
	if err != nil {
		return err
	}

	return d.Close()
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
