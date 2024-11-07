package v6

import (
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/v6/internal"
	"github.com/anchore/grype/internal/log"
)

type store struct {
	*dbMetadataStore
	*providerStore
	*vulnerabilityStore
	*affectedPackageStore
	blobStore *blobStore
	db        *gorm.DB
	config    Config
	write     bool
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

	bs := newBlobStore(db)
	return &store{
		dbMetadataStore:      newDBMetadataStore(db),
		providerStore:        newProviderStore(db),
		vulnerabilityStore:   newVulnerabilityStore(db, bs),
		affectedPackageStore: newAffectedPackageStore(db, bs),
		blobStore:            bs,
		db:                   db,
		config:               cfg,
		write:                write,
	}, nil
}

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

	desc, err := CalculateDescription(filepath.Join(s.config.DBDirPath, VulnerabilityDBFileName))
	if err != nil {
		return fmt.Errorf("failed to create description from dir: %w", err)
	}

	if desc == nil {
		return fmt.Errorf("unable to describe the database")
	}

	fh, err := os.OpenFile(filepath.Join(s.config.DBDirPath, ChecksumFileName), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open description file: %w", err)
	}

	return WriteChecksums(fh, *desc)
}
