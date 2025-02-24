package v6

import (
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type DBMetadataStoreWriter interface {
	SetDBMetadata() error
}

type DBMetadataStoreReader interface {
	GetDBMetadata() (*DBMetadata, error)
}

type dbMetadataStore struct {
	db *gorm.DB
}

func newDBMetadataStore(db *gorm.DB) *dbMetadataStore {
	return &dbMetadataStore{
		db: db,
	}
}

func (s *dbMetadataStore) GetDBMetadata() (*DBMetadata, error) {
	log.Trace("fetching DB metadata")

	var model DBMetadata

	result := s.db.First(&model)
	return &model, result.Error
}

func (s *dbMetadataStore) SetDBMetadata() error {
	log.Trace("writing DB metadata")

	if err := s.db.Where("true").Delete(&DBMetadata{}).Error; err != nil {
		return fmt.Errorf("failed to delete existing DB metadata record: %w", err)
	}

	// note: it is important to round the time to the second to avoid issues with the database update check.
	// since we are comparing timestamps that are RFC3339 formatted, it's possible that milliseconds will
	// be rounded up, causing a slight difference in candidate timestamps vs current DB timestamps.
	ts := time.Now().UTC().Round(time.Second)

	instance := &DBMetadata{
		BuildTimestamp: &ts,
		Model:          ModelVersion,
		Revision:       Revision,
		Addition:       Addition,
	}

	if err := s.db.Create(instance).Error; err != nil {
		return fmt.Errorf("failed to create DB metadata record: %w", err)
	}

	return nil
}
