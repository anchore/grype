package internal

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
)

// NewDB creates a new empty DB for writing or opens an existing one for reading from the given path.
func NewDB(dbFilePath string, models []any, truncate bool) (*gorm.DB, error) {
	db, err := gormadapter.Open(dbFilePath, gormadapter.WithTruncate(truncate))
	if err != nil {
		return nil, err
	}

	if len(models) > 0 && truncate {
		// note: never migrate if this is for reading only (if we are truncating). Migrating will change the contents
		// of the DB so any checksums verifications will fail even though this is logically a no-op.
		if err := db.AutoMigrate(models...); err != nil {
			return nil, fmt.Errorf("unable to create tables: %w", err)
		}
	}
	return db, nil
}
