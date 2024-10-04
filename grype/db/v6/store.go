package v6

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
	"github.com/anchore/grype/internal/log"
)

type store struct {
	*dbMetadataStore
	db     *gorm.DB
	config Config
	write  bool
}

func newStore(cfg Config, write bool) (*store, error) {
	db, err := gormadapter.Open(cfg.DBFilePath(), gormadapter.WithTruncate(write))
	if err != nil {
		return nil, err
	}

	if write {
		if err := db.AutoMigrate(models()...); err != nil {
			return nil, fmt.Errorf("unable to create tables: %w", err)
		}
	}

	return &store{
		dbMetadataStore: newDBMetadataStore(db),
		db:              db,
		config:          cfg,
		write:           write,
	}, nil
}

func (s *store) Close() error {
	log.Debug("closing store")
	if !s.write {
		return nil
	}

	err := s.db.Exec("VACUUM").Error
	if err != nil {
		return fmt.Errorf("failed to vacuum: %w", err)
	}

	return nil
}
