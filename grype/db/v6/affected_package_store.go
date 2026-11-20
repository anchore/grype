package v6

import (
	"errors"

	"gorm.io/gorm"
)

type AffectedPackageStoreWriter interface {
	AddAffectedPackages(packages ...*AffectedPackageHandle) error
}

type AffectedPackageStoreReader interface {
	// GetAffectedPackages returns ErrLimitReached when the results fill the limit, along with the records found up to it
	GetAffectedPackages(pkg *PackageSpecifier, config *GetPackageOptions) ([]AffectedPackageHandle, error)
}

type affectedPackageStore struct {
	db       *gorm.DB
	osStore  *operatingSystemStore
	pkgStore *packageStore
}

func newAffectedPackageStore(db *gorm.DB, bs *blobStore, oss *operatingSystemStore) *affectedPackageStore {
	return &affectedPackageStore{
		db:       db,
		osStore:  oss,
		pkgStore: newPackageStore(db, bs, oss),
	}
}

func (s *affectedPackageStore) AddAffectedPackages(packages ...*AffectedPackageHandle) error {
	return addPackagesWithOS(s.pkgStore, packages...)
}

func (s *affectedPackageStore) GetAffectedPackages(pkg *PackageSpecifier, config *GetPackageOptions) ([]AffectedPackageHandle, error) {
	results, err := getPackages[*AffectedPackageHandle](
		s.pkgStore,
		pkg,
		config,
		"affected_package_handles",
	)
	if err != nil && !errors.Is(err, ErrLimitReached) {
		return nil, err
	}

	models := make([]AffectedPackageHandle, len(results))
	for i, r := range results {
		models[i] = *r
	}
	// the records found before the limit was reached are returned along with ErrLimitReached
	return models, err
}
