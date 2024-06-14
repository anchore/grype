package v6

import (
	"github.com/anchore/grype/internal/log"
)

type AffectedPackageStore interface {
	GetPackageByName(packageName string) (*Package, error)
	GetPackageByNameAndDistro(packageName, distroName, majorVersion string, minorVersion *string) (*Package, error)
}

type affectedPackageStore struct {
	*StoreConfig
	*state
}

func NewAffectedPackageStore(cfg *StoreConfig) AffectedPackageStore {
	return &affectedPackageStore{
		StoreConfig: cfg,
		state:       cfg.state(),
	}
}

func (s *affectedPackageStore) GetPackageByName(packageName string) (*Package, error) {
	log.WithFields("name", packageName).Trace("fetching Package record")

	var pkg Package
	result := s.db.Where("package_name = ?", packageName).First(&pkg)
	if result.Error != nil {
		return nil, result.Error
	}
	return &pkg, nil
}

func (s *affectedPackageStore) GetPackageByNameAndDistro(packageName, distroName, majorVersion string, minorVersion *string) (*Package, error) {
	log.WithFields("name", packageName, "distro", distroName+"@"+majorVersion).Trace("fetching Package record")

	var pkg Package
	query := s.db.Where("package_name = ? AND operating_system.name = ? AND operating_system.major_version = ?", packageName, distroName, majorVersion)
	if minorVersion != nil {
		query = query.Where("operating_system.minor_version = ?", *minorVersion)
	}
	result := query.Joins("OperatingSystem").First(&pkg)
	if result.Error != nil {
		return nil, result.Error
	}
	return &pkg, nil
}
