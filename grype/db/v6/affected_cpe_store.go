package v6

import (
	"gorm.io/gorm"

	"github.com/anchore/syft/syft/cpe"
)

type AffectedCPEStoreWriter interface {
	AddAffectedCPEs(packages ...*AffectedCPEHandle) error
}

type AffectedCPEStoreReader interface {
	GetAffectedCPEs(cpe *cpe.Attributes, config *GetCPEOptions) ([]AffectedCPEHandle, error)
}

type affectedCPEStore struct {
	db        *gorm.DB
	blobStore *blobStore
	cpeStore  *cpeStore
}

func newAffectedCPEStore(db *gorm.DB, bs *blobStore) *affectedCPEStore {
	return &affectedCPEStore{
		db:        db,
		blobStore: bs,
		cpeStore:  newCPEStore(db, bs),
	}
}

func (s *affectedCPEStore) AddAffectedCPEs(packages ...*AffectedCPEHandle) error {
	return addCPEHandles(s.cpeStore, packages...)
}

func (s *affectedCPEStore) GetAffectedCPEs(cpe *cpe.Attributes, config *GetCPEOptions) ([]AffectedCPEHandle, error) {
	results, err := getCPEHandles[*AffectedCPEHandle](
		s.cpeStore,
		cpe,
		config,
		"affected_cpe_handles",
	)
	if err != nil {
		return nil, err
	}

	models := make([]AffectedCPEHandle, len(results))
	for i, r := range results {
		models[i] = *r
	}
	return models, nil
}
