package v6

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/v6/internal"
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
	write     bool
}

func (s *store) GetDB() *gorm.DB {
	return s.db
}

func newStore(cfg Config, write bool) (*store, error) {
	var path string
	if cfg.DBDirPath != "" {
		path = cfg.DBFilePath()
	}
	db, err := internal.NewDB(path, Models(), write)
	if err != nil {
		return nil, fmt.Errorf("failed to open db: %w", err)
	}

	if write {
		// add hard-coded os aliases
		if err := db.Create(KnownOperatingSystemAliases()).Error; err != nil {
			return nil, fmt.Errorf("failed to add os aliases: %w", err)
		}
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
		write:                write,
	}, nil
}

// Close closes the store and finalizes the blobs when the DB is open for writing. If open for reading, it does nothing.
func (s *store) Close() error {
	log.Debug("closing store")
	if !s.write {
		return nil
	}

	if err := s.blobStore.Close(); err != nil {
		return fmt.Errorf("failed to finalize blobs: %w", err)
	}

	err := s.db.Exec("VACUUM").Error
	if err != nil {
		return fmt.Errorf("failed to vacuum: %w", err)
	}

	return nil
}
