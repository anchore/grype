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
	log.Trace("fetching DB metadata record")

	var model DBMetadata

	result := s.db.First(&model)
	return &model, result.Error
}

func (s *dbMetadataStore) SetDBMetadata() error {
	log.Trace("writing DB metadata record")

	if err := s.db.Unscoped().Where("true").Delete(&DBMetadata{}).Error; err != nil {
		return fmt.Errorf("failed to delete existing DB metadata record: %w", err)
	}

	ts := time.Now().UTC()
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
