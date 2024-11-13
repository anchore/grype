package v6

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type AffectedCPEStoreWriter interface {
	AddAffectedCPEs(packages ...*AffectedCPEHandle) error
}

type AffectedCPEStoreReader interface {
	GetCPEsByProduct(packageName string, config *GetAffectedCPEOptions) ([]AffectedCPEHandle, error)
}

type GetAffectedCPEOptions struct {
	PreloadCPE  bool
	PreloadBlob bool
}

type affectedCPEStore struct {
	db        *gorm.DB
	blobStore *blobStore
}

func newAffectedCPEStore(db *gorm.DB, bs *blobStore) *affectedCPEStore {
	return &affectedCPEStore{
		db:        db,
		blobStore: bs,
	}
}

// AddAffectedCPEs adds one or more affected CPEs to the store
func (s *affectedCPEStore) AddAffectedCPEs(packages ...*AffectedCPEHandle) error {
	for _, pkg := range packages {
		if err := s.blobStore.addBlobable(pkg); err != nil {
			return fmt.Errorf("unable to add affected package blob: %w", err)
		}

		if err := s.db.Create(pkg).Error; err != nil {
			return fmt.Errorf("unable to add affected CPE: %w", err)
		}
	}
	return nil
}

// GetCPEsByProduct retrieves a single AffectedCPEHandle by product name
func (s *affectedCPEStore) GetCPEsByProduct(packageName string, config *GetAffectedCPEOptions) ([]AffectedCPEHandle, error) {
	if config == nil {
		config = &GetAffectedCPEOptions{}
	}

	log.WithFields("product", packageName).Trace("fetching AffectedCPE record")

	var pkgs []AffectedCPEHandle
	query := s.db.
		Joins("JOIN cpes ON cpes.id = affected_cpe_handles.cpe_id").
		Where("cpes.product = ?", packageName)

	query = s.handlePreload(query, *config)

	err := query.Find(&pkgs).Error
	if err != nil {
		return nil, fmt.Errorf("unable to fetch affected package record: %w", err)
	}

	if config.PreloadBlob {
		for i := range pkgs {
			err := s.attachBlob(&pkgs[i])
			if err != nil {
				return nil, fmt.Errorf("unable to attach blob %#v: %w", pkgs[i], err)
			}
		}
	}

	return pkgs, nil
}

func (s *affectedCPEStore) handlePreload(query *gorm.DB, config GetAffectedCPEOptions) *gorm.DB {
	if config.PreloadCPE {
		query = query.Preload("CPE")
	}

	return query
}

// attachBlob attaches the BlobValue to the AffectedCPEHandle
func (s *affectedCPEStore) attachBlob(cpe *AffectedCPEHandle) error {
	var blobValue *AffectedPackageBlob

	rawValue, err := s.blobStore.getBlobValue(cpe.BlobID)
	if err != nil {
		return fmt.Errorf("unable to fetch blob value for affected CPE: %w", err)
	}

	if err := json.Unmarshal([]byte(rawValue), &blobValue); err != nil {
		return fmt.Errorf("unable to unmarshal blob value: %w", err)
	}

	cpe.BlobValue = blobValue
	return nil
}
