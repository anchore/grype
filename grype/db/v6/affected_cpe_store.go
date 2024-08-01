package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
)

type AffectedCPEStoreWriter interface {
	AddAffectedCPEs(packages ...*AffectedCPEHandle) error
}

type AffectedCPEStoreReader interface {
	GetCPEsByProduct(packageName string) (*AffectedCPEHandle, error)
}

type affectedCPEStore struct {
	*StoreConfig
	*state
	blobStore *blobStore
}

func newAffectedCPEStore(cfg *StoreConfig, bs *blobStore) *affectedCPEStore {
	return &affectedCPEStore{
		StoreConfig: cfg,
		state:       cfg.state(),
		blobStore:   bs,
	}
}

func (s *affectedCPEStore) AddAffectedCPEs(packages ...*AffectedCPEHandle) error {
	for _, v := range packages {
		if err := s.blobStore.AddAffectedCPEBlob(v); err != nil {
			return fmt.Errorf("unable to add affected blob: %w", err)
		}

		if err := s.db.Create(v).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *affectedCPEStore) GetCPEsByProduct(packageName string) (*AffectedCPEHandle, error) {
	log.WithFields("name", packageName).Trace("fetching PackageCPE record")
	panic("not implemented")
	//var pkg AffectedPackageHandle
	//result := s.db.Where("package_name = ?", packageName).First(&pkg)
	//if result.Error != nil {
	//	return nil, result.Error
	//}
	//return &pkg, nil
}
