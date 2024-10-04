package v6

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
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

	fs := afero.NewOsFs()

	desc, err := NewDescriptionFromDir(fs, s.config.DBDirPath)
	if err != nil {
		return fmt.Errorf("failed to create description from dir: %w", err)
	}

	if desc == nil {
		return fmt.Errorf("unable to describe the database")
	}

	fh, err := fs.OpenFile(filepath.Join(s.config.DBDirPath, DescriptionFileName), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open description file: %w", err)
	}

	return writeDescription(fh, *desc)
}
