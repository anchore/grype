package internal

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/grype/db/internal/gormadapter"
)

func NewDB(dbFilePath string, models []any, truncate bool) (*gorm.DB, error) {
	db, err := gormadapter.Open(dbFilePath, gormadapter.WithTruncate(truncate))
	if err != nil {
		return nil, err
	}

	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			return nil, fmt.Errorf("unable to create tables: %w", err)
		}
	}
	return db, nil
}
