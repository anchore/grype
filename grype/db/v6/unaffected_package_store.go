package v6

import "gorm.io/gorm"

type UnaffectedPackageStoreWriter interface {
	AddUnaffectedPackages(packages ...*UnaffectedPackageHandle) error
}

type UnaffectedPackageStoreReader interface {
	GetUnaffectedPackages(pkg *PackageSpecifier, config *GetPackageOptions) ([]UnaffectedPackageHandle, error)
}
type unaffectedPackageStore struct {
	db       *gorm.DB
	osStore  *operatingSystemStore
	pkgStore *packageStore
}

func newUnaffectedPackageStore(db *gorm.DB, bs *blobStore, oss *operatingSystemStore) *unaffectedPackageStore {
	return &unaffectedPackageStore{
		db:       db,
		osStore:  oss,
		pkgStore: newPackageStore(db, bs, oss),
	}
}

func (s *unaffectedPackageStore) AddUnaffectedPackages(packages ...*UnaffectedPackageHandle) error {
	return addPackagesWithOS(s.pkgStore, packages...)
}

func (s *unaffectedPackageStore) GetUnaffectedPackages(pkg *PackageSpecifier, config *GetPackageOptions) ([]UnaffectedPackageHandle, error) {
	results, err := getPackages[*UnaffectedPackageHandle](
		s.pkgStore,
		pkg,
		config,
		"unaffected_package_handles",
	)
	if err != nil {
		return nil, err
	}

	models := make([]UnaffectedPackageHandle, len(results))
	for i, r := range results {
		models[i] = *r
	}
	return models, nil
}
