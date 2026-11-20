package v6

import (
	"errors"

	"gorm.io/gorm"

	"github.com/anchore/syft/syft/cpe"
)

type UnaffectedCPEStoreWriter interface {
	AddUnaffectedCPEs(packages ...*UnaffectedCPEHandle) error
}

type UnaffectedCPEStoreReader interface {
	// GetUnaffectedCPEs returns ErrLimitReached when the results fill the limit, along with the records found up to it
	GetUnaffectedCPEs(cpe *cpe.Attributes, config *GetCPEOptions) ([]UnaffectedCPEHandle, error)
}

type unaffectedCPEStore struct {
	db        *gorm.DB
	blobStore *blobStore
	cpeStore  *cpeStore
}

func newUnaffectedCPEStore(db *gorm.DB, bs *blobStore) *unaffectedCPEStore {
	return &unaffectedCPEStore{
		db:        db,
		blobStore: bs,
		cpeStore:  newCPEStore(db, bs),
	}
}

func (s *unaffectedCPEStore) AddUnaffectedCPEs(packages ...*UnaffectedCPEHandle) error {
	return addCPEHandles(s.cpeStore, packages...)
}

func (s *unaffectedCPEStore) GetUnaffectedCPEs(cpe *cpe.Attributes, config *GetCPEOptions) ([]UnaffectedCPEHandle, error) {
	results, err := getCPEHandles[*UnaffectedCPEHandle](
		s.cpeStore,
		cpe,
		config,
		"unaffected_cpe_handles",
	)
	if err != nil && !errors.Is(err, ErrLimitReached) {
		return nil, err
	}

	models := make([]UnaffectedCPEHandle, len(results))
	for i, r := range results {
		models[i] = *r
	}
	// the records found before the limit was reached are returned along with ErrLimitReached
	return models, err
}
