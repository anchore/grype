package v6

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

var NoDistroSpecified = &DistroSpecifier{}
var AnyDistroSpecified *DistroSpecifier
var ErrMissingDistroIdentification = errors.New("missing distro name or codename")
var ErrDistroNotPresent = errors.New("distro not present")
var ErrMultipleOSMatches = errors.New("multiple OS matches found but not allowed")

type GetAffectedPackageOptions struct {
	PreloadOS      bool
	PreloadPackage bool
	PreloadBlob    bool
	PackageType    string
	Distro         *DistroSpecifier
}

// DistroSpecifier is a struct that represents a distro in a way that can be used to query the affected package store.
type DistroSpecifier struct {
	// Name of the distro as identified by the ID field in /etc/os-release
	Name string

	// MajorVersion is the first field in the VERSION_ID field in /etc/os-release (e.g. 7 in "7.0.1406")
	MajorVersion string

	// MinorVersion is the second field in the VERSION_ID field in /etc/os-release (e.g. 0 in "7.0.1406")
	MinorVersion string

	// LabelVersion is mutually exclusive to MajorVersion and MinorVersion and tends to represent the
	// VERSION_ID when it is not a version number (e.g. "edge" or "unstable")
	LabelVersion string

	// Codename is the CODENAME field in /etc/os-release (e.g. "wheezy" for debian 7)
	Codename string

	// AllowMultiple specifies whether we intend to allow for multiple distro identities to be matched.
	AllowMultiple bool
}

func (d DistroSpecifier) version() string {
	if d.MajorVersion != "" && d.MinorVersion != "" {
		return d.MajorVersion + "." + d.MinorVersion
	}

	if d.MajorVersion != "" {
		return d.MajorVersion
	}

	if d.LabelVersion != "" {
		return d.LabelVersion
	}

	if d.Codename != "" {
		return d.Codename
	}

	return ""
}

func (d DistroSpecifier) matchesVersionPattern(pattern string) bool {
	// check if version or version label matches the given regex
	r, err := regexp.Compile(pattern)
	if err != nil {
		log.Tracef("failed to compile distro specifier regex pattern %q: %v", pattern, err)
		return false
	}

	if r.MatchString(d.version()) {
		return true
	}

	if d.LabelVersion != "" {
		return r.MatchString(d.LabelVersion)
	}
	return false
}

type AffectedPackageStoreWriter interface {
	AddAffectedPackages(packages ...*AffectedPackageHandle) error
}

type AffectedPackageStoreReader interface {
	GetAffectedPackagesByName(packageName string, config *GetAffectedPackageOptions) ([]AffectedPackageHandle, error)
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

func (s *affectedPackageStore) GetAffectedPackagesByName(packageName string, config *GetAffectedPackageOptions) ([]AffectedPackageHandle, error) {
	if config == nil {
		config = &GetAffectedPackageOptions{}
	}

	log.WithFields("name", packageName, "distro", distroDisplay(config.Distro)).Trace("fetching AffectedPackage record")

	if hasDistroSpecified(config.Distro) {
		return s.getPackageByNameAndDistro(packageName, *config)
	}

	return s.getNonDistroPackageByName(packageName, *config)
}

func (s *affectedPackageStore) getNonDistroPackageByName(packageName string, config GetAffectedPackageOptions) ([]AffectedPackageHandle, error) {
	var pkgs []AffectedPackageHandle
	query := s.db.Joins("JOIN packages ON affected_package_handles.package_id = packages.id")

	if config.Distro != AnyDistroSpecified {
		query = query.Where("operating_system_id IS NULL")
	}

	query = s.handlePackage(query, packageName, config)
	query = s.handlePreload(query, config)

	err := query.Find(&pkgs).Error

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

func (s *affectedPackageStore) getPackageByNameAndDistro(packageName string, config GetAffectedPackageOptions) ([]AffectedPackageHandle, error) {
	var resolvedDistros []OperatingSystem
	var err error
	if config.Distro != NoDistroSpecified || config.Distro != AnyDistroSpecified {
		resolvedDistros, err = s.resolveDistro(*config.Distro)
		if err != nil {
			return nil, fmt.Errorf("unable to resolve distro: %w", err)
		}

		switch {
		case len(resolvedDistros) == 0:
			return nil, ErrDistroNotPresent
		case len(resolvedDistros) > 1 && !config.Distro.AllowMultiple:
			return nil, ErrMultipleOSMatches
		}
	}

	var pkgs []AffectedPackageHandle
	query := s.db.Joins("JOIN packages ON affected_package_handles.package_id = packages.id").
		Joins("JOIN operating_systems ON affected_package_handles.operating_system_id = operating_systems.id")

	query = s.handlePackage(query, packageName, config)
	query = s.handleDistros(query, resolvedDistros)
	query = s.handlePreload(query, config)

	err = query.Find(&pkgs).Error
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

func (s *affectedPackageStore) resolveDistro(d DistroSpecifier) ([]OperatingSystem, error) {
	if d.Name == "" && d.Codename == "" {
		return nil, ErrMissingDistroIdentification
	}

	// search for aliases for the given distro; we intentionally map some OSs to other OSs in terms of
	// vulnerability (e.g. `centos` is an alias for `rhel`). If an alias is found always use that alias in
	// searches (there will never be anything in the DB for aliased distros).
	if err := s.applyAlias(&d); err != nil {
		return nil, err
	}

	query := s.db.Model(&OperatingSystem{})

	if d.Name != "" {
		query = query.Where("name = ?", d.Name)
	}

	if d.Codename != "" {
		query = query.Where("codename = ?", d.Codename)
	}

	if d.LabelVersion != "" {
		query = query.Where("label_version = ?", d.LabelVersion)
	}

	return s.searchForDistroVersionVariants(query, d)
}

func (s *affectedPackageStore) searchForDistroVersionVariants(query *gorm.DB, d DistroSpecifier) ([]OperatingSystem, error) {
	var allOs []OperatingSystem

	handleQuery := func(q *gorm.DB, desc string) ([]OperatingSystem, error) {
		err := q.Find(&allOs).Error
		if err == nil {
			return allOs, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("failed to query distro by %s: %w", desc, err)
		}
		return nil, nil
	}

	if d.MajorVersion == "" && d.MinorVersion == "" {
		return handleQuery(query, "name and codename only")
	}

	// search by the most specific criteria first, then fallback

	var result []OperatingSystem
	var err error
	if d.MajorVersion != "" {
		if d.MinorVersion != "" {
			// non-empty major and minor versions
			specificQuery := query.Session(&gorm.Session{}).Where("major_version = ? AND minor_version = ?", d.MajorVersion, d.MinorVersion)
			result, err = handleQuery(specificQuery, "major and minor versions")
			if err != nil || len(result) > 0 {
				return result, err
			}
		}

		// fallback to major version only, requiring the minor version to be blank. Note: it is important that we don't
		// match on any record with the given major version, we must only match on records that are intentionally empty
		// minor version. For instance, the DB may have rhel 8.1, 8.2, 8.3, 8.4, etc. We don't want to arbitrarily match
		// on one of these or match even the latest version, as even that may yield incorrect vulnerability matching
		// results. We are only intending to allow matches for when the vulnerability data is only specified at the major version level.
		majorExclusiveQuery := query.Session(&gorm.Session{}).Where("major_version = ? AND minor_version = ?", d.MajorVersion, "")
		result, err = handleQuery(majorExclusiveQuery, "exclusively major version")
		if err != nil || len(result) > 0 {
			return result, err
		}

		// fallback to major version for any minor version
		majorQuery := query.Session(&gorm.Session{}).Where("major_version = ?", d.MajorVersion)
		result, err = handleQuery(majorQuery, "major version with any minor version")
		if err != nil || len(result) > 0 {
			return result, err
		}
	}

	return allOs, nil
}

func (s *affectedPackageStore) applyAlias(d *DistroSpecifier) error {
	if d.Name == "" {
		return nil
	}

	var aliases []OperatingSystemAlias
	err := s.db.Where("name = ?", d.Name).Find(&aliases).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to resolve alias for distro %q: %w", d.Name, err)
		}
		return nil
	}

	var alias *OperatingSystemAlias

	for _, a := range aliases {
		if a.Codename != "" && a.Codename != d.Codename {
			continue
		}

		if a.Version != "" && a.Version != d.version() {
			continue
		}

		if a.VersionPattern != "" && !d.matchesVersionPattern(a.VersionPattern) {
			continue
		}

		alias = &a
		break
	}

	if alias == nil {
		return nil
	}

	if alias.ReplacementName != nil {
		d.Name = *alias.ReplacementName
	}

	if alias.Rolling {
		d.MajorVersion = ""
		d.MinorVersion = ""
	}

	if alias.ReplacementMajorVersion != nil {
		d.MajorVersion = *alias.ReplacementMajorVersion
	}

	if alias.ReplacementMinorVersion != nil {
		d.MinorVersion = *alias.ReplacementMinorVersion
	}

	if alias.ReplacementLabelVersion != nil {
		d.LabelVersion = *alias.ReplacementLabelVersion
	}

	return nil
}

func (s *affectedPackageStore) handlePackage(query *gorm.DB, packageName string, config GetAffectedPackageOptions) *gorm.DB {
	query = query.Where("packages.name = ?", packageName)

	if config.PackageType != "" {
		query = query.Where("packages.type = ?", config.PackageType)
	}
	return query
}

func (s *affectedPackageStore) handleDistros(query *gorm.DB, resolvedDistros []OperatingSystem) *gorm.DB {
	var count int
	for _, o := range resolvedDistros {
		if o.ID != 0 {
			if count == 0 {
				query = query.Where("operating_systems.id = ?", o.ID)
			} else {
				query = query.Or("operating_systems.id = ?", o.ID)
			}
			count++
		}
	}
	return query
}

func (s *affectedPackageStore) handlePreload(query *gorm.DB, config GetAffectedPackageOptions) *gorm.DB {
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
