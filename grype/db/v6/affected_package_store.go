package v6

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

var NoDistroSpecified = &DistroSpecifier{}
var AnyDistroSpecified *DistroSpecifier

type GetAffectedOptions struct {
	PreloadOS      bool
	PreloadPackage bool
	PreloadBlob    bool
	Distro         *DistroSpecifier
}

type DistroSpecifier struct {
	Name         string
	MajorVersion string
	MinorVersion string
	Codename     string
}

type AffectedPackageStoreWriter interface {
	AddAffectedPackages(packages ...*AffectedPackageHandle) error
}

type AffectedPackageStoreReader interface {
	GetAffectedPackagesByName(packageName string, config *GetAffectedOptions) ([]AffectedPackageHandle, error)
}

type affectedPackageStore struct {
	db        *gorm.DB
	blobStore *blobStore
}

func newAffectedPackageStore(db *gorm.DB, bs *blobStore) *affectedPackageStore {
	return &affectedPackageStore{
		db:        db,
		blobStore: bs,
	}
}

func (s *affectedPackageStore) AddAffectedPackages(packages ...*AffectedPackageHandle) error {
	for _, v := range packages {
		if v.Package != nil {
			var existingPackage Package
			result := s.db.Where("name = ? AND type = ?", v.Package.Name, v.Package.Type).FirstOrCreate(&existingPackage, v.Package)
			if result.Error != nil {
				return fmt.Errorf("failed to create package (name=%q type=%q): %w", v.Package.Name, v.Package.Type, result.Error)
			}
			v.Package = &existingPackage
		}

		if err := s.blobStore.addBlobable(v); err != nil {
			return fmt.Errorf("unable to add affected blob: %w", err)
		}
		if err := s.db.Create(v).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *affectedPackageStore) GetAffectedPackagesByName(packageName string, config *GetAffectedOptions) ([]AffectedPackageHandle, error) {
	if config == nil {
		config = &GetAffectedOptions{}
	}

	log.WithFields("name", packageName, "distro", distroDisplay(config.Distro)).Trace("fetching AffectedPackage record")

	if hasDistroSpecified(config.Distro) {
		return s.getPackageByNameAndDistro(packageName, *config)
	}

	return s.getNonDistroPackageByName(packageName, *config)
}

func (s *affectedPackageStore) getNonDistroPackageByName(packageName string, config GetAffectedOptions) ([]AffectedPackageHandle, error) {
	var pkgs []AffectedPackageHandle
	query := s.db.Joins("JOIN packages ON affected_package_handles.package_id = packages.id").
		Where("packages.name = ?", packageName)
	if config.Distro != AnyDistroSpecified {
		query = query.Where("operating_system_id IS NULL")
	}

	err := s.handlePreload(query, config).Find(&pkgs).Error

	if err != nil {
		return nil, fmt.Errorf("unable to fetch non-distro affected package record: %w", err)
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

func (s *affectedPackageStore) getPackageByNameAndDistro(packageName string, config GetAffectedOptions) ([]AffectedPackageHandle, error) {
	var pkgs []AffectedPackageHandle
	query := s.db.Joins("JOIN packages ON affected_package_handles.package_id = packages.id").
		Joins("JOIN operating_systems ON affected_package_handles.operating_system_id = operating_systems.id").
		Where("packages.name = ?", packageName)

	err := s.handleDistroAndPreload(query, config).Find(&pkgs).Error

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

func (s *affectedPackageStore) handleDistroAndPreload(query *gorm.DB, config GetAffectedOptions) *gorm.DB {
	query = s.handleDistro(query, config.Distro)
	query = s.handlePreload(query, config)
	return query
}

func (s *affectedPackageStore) handleDistro(query *gorm.DB, d *DistroSpecifier) *gorm.DB {
	if d == AnyDistroSpecified {
		return query
	}

	if d.Name != "" {
		query = query.Where("operating_systems.name = ?", d.Name)
	}

	if d.Codename != "" {
		query = query.Where("operating_systems.codename = ?", d.Codename)
	}

	if d.MajorVersion != "" {
		query = query.Where("operating_systems.major_version = ?", d.MajorVersion)
	}

	if d.MinorVersion != "" {
		query = query.Where("operating_systems.minor_version = ?", d.MinorVersion)
	}
	return query
}

func (s *affectedPackageStore) handlePreload(query *gorm.DB, config GetAffectedOptions) *gorm.DB {
	if config.PreloadPackage {
		query = query.Preload("Package")
	}

	if config.PreloadOS {
		query = query.Preload("OperatingSystem")
	}
	return query
}

func (s *affectedPackageStore) attachBlob(vh *AffectedPackageHandle) error {
	var blobValue *AffectedPackageBlob

	rawValue, err := s.blobStore.getBlobValue(vh.BlobID)
	if err != nil {
		return fmt.Errorf("unable to fetch affected package blob value: %w", err)
	}

	err = json.Unmarshal([]byte(rawValue), &blobValue)
	if err != nil {
		return fmt.Errorf("unable to unmarshal affected package blob value: %w", err)
	}

	vh.BlobValue = blobValue

	return nil
}

func distroDisplay(d *DistroSpecifier) string {
	if d == nil {
		return "any"
	}

	if *d == *NoDistroSpecified {
		return "none"
	}

	var version string
	if d.MajorVersion != "" {
		version = d.MajorVersion
		if d.MinorVersion != "" {
			version += "." + d.MinorVersion
		}
	} else {
		version = d.Codename
	}

	distroDisplayName := d.Name
	if version != "" {
		distroDisplayName += "@" + version
	}
	if version == d.MajorVersion && d.Codename != "" {
		distroDisplayName += " (" + d.Codename + ")"
	}

	return distroDisplayName
}

func hasDistroSpecified(d *DistroSpecifier) bool {
	if d == AnyDistroSpecified {
		return false
	}

	if *d == *NoDistroSpecified {
		return false
	}
	return true
}
