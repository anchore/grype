package v6

import (
	"fmt"
	"github.com/anchore/grype/internal/log"
)

type AffectedPackageStoreWriter interface {
	AddAffectedPackages(packages ...*AffectedPackageHandle) error
}

type AffectedPackageStoreReader interface {
	//GetPackageByName(packageName string) (*AffectedPackageHandle, error)
	GetPackageByNameAndDistro(packageName, distroName, majorVersion string, minorVersion *string) ([]AffectedPackageHandle, error)
}

type affectedPackageStore struct {
	*StoreConfig
	*state
	blobStore *blobStore
}

func newAffectedPackageStore(cfg *StoreConfig, bs *blobStore) *affectedPackageStore {
	return &affectedPackageStore{
		StoreConfig: cfg,
		state:       cfg.state(),
		blobStore:   bs,
	}
}

func (s *affectedPackageStore) AddAffectedPackages(packages ...*AffectedPackageHandle) error {
	for _, v := range packages {
		if v.Package != nil {
			var existingPackage Package
			result := s.db.Where("name = ? AND type = ?", v.Package.Name, v.Package.Type).FirstOrCreate(&existingPackage, v.Package)
			if result.Error != nil {
				return fmt.Errorf("failed to create package (name=%q type=%q): %w", v.Package.Name, v.Package.Type, result.Error)
			} else {
				v.Package = &existingPackage
			}
		}

		if err := s.blobStore.AddAffectedPackageBlob(v); err != nil {
			return fmt.Errorf("unable to add affected blob: %w", err)
		}
		if err := s.db.Create(v).Error; err != nil {
			return err
		}
	}
	return nil
}

//
//func (s *affectedPackageStore) GetPackageByName(packageName string) (*AffectedPackageHandle, error) {
//	log.WithFields("name", packageName).Trace("fetching Package record")
//	panic("not implemented")
//	//var pkg AffectedPackageHandle
//	//result := s.db.Where("package_name = ?", packageName).First(&pkg)
//	//if result.Error != nil {
//	//	return nil, result.Error
//	//}
//	//return &pkg, nil
//}

func (s *affectedPackageStore) GetPackageByNameAndDistro(packageName, distroName, majorVersion string, minorVersion *string) ([]AffectedPackageHandle, error) {
	version := majorVersion
	if minorVersion != nil {
		version = majorVersion + "." + *minorVersion
	}
	log.WithFields("name", packageName, "distro", distroName+"@"+version).Trace("fetching Package record")

	var pkgs []AffectedPackageHandle
	query := s.db.Where("package_name = ? AND operating_system.name = ? AND operating_system.major_version = ?", packageName, distroName, majorVersion)
	// TODO: can this be combined into a single query? does it honor null vars?
	if minorVersion != nil {
		query = query.Where("operating_system.minor_version = ?", *minorVersion)
	} else {
		query = query.Where("operating_system.minor_version = null")
	}
	result := query.Joins("OperatingSystem").Find(&pkgs)
	if result.Error != nil {
		return nil, result.Error
	}
	return pkgs, nil
}
