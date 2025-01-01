package v6

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

const (
	// batchSize affects how many records are fetched at a time from the DB. Note: when using preload, row entries
	// for related records may convey as parameters in a "WHERE x in (...)" which can lead to a large number of
	// parameters in the query -- if above 999 then this will result in an error for sqlite. For this reason we
	// try to keep this value well below 999.
	batchSize = 300
	anyPkg    = "any"
	anyOS     = "any"
)

var NoOSSpecified = &OSSpecifier{}
var AnyOSSpecified *OSSpecifier
var ErrMissingDistroIdentification = errors.New("missing os name or codename")
var ErrDistroNotPresent = errors.New("distro not present")
var ErrMultipleOSMatches = errors.New("multiple OS matches found but not allowed")
var ErrLimitReached = errors.New("query limit reached")

type GetAffectedPackageOptions struct {
	PreloadOS            bool
	PreloadPackage       bool
	PreloadPackageCPEs   bool
	PreloadVulnerability bool
	PreloadBlob          bool
	OSs                  OSSpecifiers
	Vulnerabilities      VulnerabilitySpecifiers
	Limit                int
}

type PackageSpecifiers []*PackageSpecifier

type PackageSpecifier struct {
	Name string
	Type string
	CPE  *cpe.Attributes
}

func (p *PackageSpecifier) String() string {
	if p == nil {
		return anyPkg
	}

	var args []string
	if p.Name != "" {
		args = append(args, fmt.Sprintf("name=%s", p.Name))
	}

	if p.Type != "" {
		args = append(args, fmt.Sprintf("type=%s", p.Type))
	}

	if p.CPE != nil {
		args = append(args, fmt.Sprintf("cpe=%s", p.CPE.String()))
	}

	if len(args) > 0 {
		return fmt.Sprintf("package(%s)", strings.Join(args, ", "))
	}

	return anyPkg
}

func (p PackageSpecifiers) String() string {
	if len(p) == 0 {
		return anyPkg
	}

	var parts []string
	for _, v := range p {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

type OSSpecifiers []*OSSpecifier

// OSSpecifier is a struct that represents a distro in a way that can be used to query the affected package store.
type OSSpecifier struct {
	// Name of the distro as identified by the ID field in /etc/os-release (or similar normalized name, e.g. "oracle" instead of "ol")
	Name string

	// MajorVersion is the first field in the VERSION_ID field in /etc/os-release (e.g. 7 in "7.0.1406")
	MajorVersion string

	// MinorVersion is the second field in the VERSION_ID field in /etc/os-release (e.g. 0 in "7.0.1406")
	MinorVersion string

	// LabelVersion is a string that represents a floating version (e.g. "edge" or "unstable") or is the CODENAME field in /etc/os-release (e.g. "wheezy" for debian 7)
	LabelVersion string

	// AllowMultiple specifies whether we intend to allow for multiple distro identities to be matched.
	AllowMultiple bool
}

func (d *OSSpecifier) String() string {
	if d == nil {
		return anyOS
	}

	if *d == *NoOSSpecified {
		return "none"
	}

	var version string
	if d.MajorVersion != "" {
		version = d.MajorVersion
		if d.MinorVersion != "" {
			version += "." + d.MinorVersion
		}
	} else {
		version = d.LabelVersion
	}

	distroDisplayName := d.Name
	if version != "" {
		distroDisplayName += "@" + version
	}
	if version == d.MajorVersion && d.LabelVersion != "" {
		distroDisplayName += " (" + d.LabelVersion + ")"
	}

	return distroDisplayName
}

func (d OSSpecifier) version() string {
	if d.MajorVersion != "" && d.MinorVersion != "" {
		return d.MajorVersion + "." + d.MinorVersion
	}

	if d.MajorVersion != "" {
		return d.MajorVersion
	}

	if d.LabelVersion != "" {
		return d.LabelVersion
	}

	return ""
}

func (d OSSpecifiers) String() string {
	if d.IsAny() {
		return anyOS
	}
	var parts []string
	for _, v := range d {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ", ")
}

func (d OSSpecifiers) IsAny() bool {
	if len(d) == 0 {
		return true
	}
	if len(d) == 1 && d[0] == AnyOSSpecified {
		return true
	}
	return false
}

func (d OSSpecifier) matchesVersionPattern(pattern string) bool {
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
	GetAffectedPackages(pkg *PackageSpecifier, config *GetAffectedPackageOptions) ([]AffectedPackageHandle, error)
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
		if err := s.blobStore.addBlobable(v); err != nil {
			return fmt.Errorf("unable to add affected blob: %w", err)
		}
		if err := s.db.Create(v).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *affectedPackageStore) GetAffectedPackages(pkg *PackageSpecifier, config *GetAffectedPackageOptions) ([]AffectedPackageHandle, error) {
	if config == nil {
		config = &GetAffectedPackageOptions{}
	}

	start := time.Now()
	defer func() {
		log.WithFields("pkg", pkg.String(), "distro", config.OSs, "vulns", config.Vulnerabilities, "duration", time.Since(start)).Trace("fetched affected package record")
	}()

	query := s.handlePackage(s.db, pkg)

	var err error
	query, err = s.handleVulnerabilityOptions(query, config.Vulnerabilities)
	if err != nil {
		return nil, err
	}

	query, err = s.handleOSOptions(query, config.OSs)
	if err != nil {
		return nil, err
	}

	query = s.handlePreload(query, *config)

	var models []AffectedPackageHandle

	var results []*AffectedPackageHandle
	if err := query.FindInBatches(&results, batchSize, func(_ *gorm.DB, _ int) error { // nolint:dupl
		if config.PreloadBlob {
			var blobs []blobable
			for _, r := range results {
				blobs = append(blobs, r)
			}
			if err := s.blobStore.attachBlobValue(blobs...); err != nil {
				return fmt.Errorf("unable to attach blobs: %w", err)
			}
		}

		if config.PreloadVulnerability {
			var vulns []blobable
			for _, r := range results {
				if r.Vulnerability != nil {
					vulns = append(vulns, r.Vulnerability)
				}
			}
			if err := s.blobStore.attachBlobValue(vulns...); err != nil {
				return fmt.Errorf("unable to attach vulnerability blob: %w", err)
			}
		}

		for _, r := range results {
			models = append(models, *r)
		}

		if config.Limit > 0 && len(models) >= config.Limit {
			return ErrLimitReached
		}

		return nil
	}).Error; err != nil {
		return models, fmt.Errorf("unable to fetch affected package records: %w", err)
	}

	return models, nil
}

func LogQuery(tx *gorm.DB, findTarget any) {
	log.Tracef("executing query: %v", tx.ToSQL(func(tx *gorm.DB) *gorm.DB {
		return tx.Find(&findTarget)
	}))
}

func (s *affectedPackageStore) handlePackage(query *gorm.DB, config *PackageSpecifier) *gorm.DB {
	if config == nil {
		return query
	}

	query = query.Joins("JOIN packages ON affected_package_handles.package_id = packages.id")

	if config.Name != "" {
		query = query.Where("packages.name = ?", config.Name)
	}
	if config.Type != "" {
		query = query.Where("packages.type = ?", config.Type)
	}

	if config.CPE != nil {
		query = query.Joins("JOIN cpes ON packages.id = cpes.package_id")
		query = handleCPEOptions(query, config.CPE)
	}

	return query
}

func (s *affectedPackageStore) handleVulnerabilityOptions(query *gorm.DB, configs []VulnerabilitySpecifier) (*gorm.DB, error) {
	if len(configs) == 0 {
		return query, nil
	}
	query = query.Joins("JOIN vulnerability_handles ON affected_package_handles.vulnerability_id = vulnerability_handles.id")

	return handleVulnerabilityOptions(s.db, query, configs...)
}

func (s *affectedPackageStore) handleOSOptions(query *gorm.DB, configs []*OSSpecifier) (*gorm.DB, error) {
	resolvedDistroMap := make(map[int64]OperatingSystem)

	if len(configs) == 0 {
		configs = append(configs, AnyOSSpecified)
	}

	var hasAny, hasNone, hasSpecific bool
	for _, config := range configs {
		switch {
		case hasDistroSpecified(config):
			curResolvedDistros, err := s.resolveDistro(*config)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve distro: %w", err)
			}

			switch {
			case len(curResolvedDistros) == 0:
				return nil, ErrDistroNotPresent
			case len(curResolvedDistros) > 1 && !config.AllowMultiple:
				return nil, ErrMultipleOSMatches
			}
			hasSpecific = true
			for _, d := range curResolvedDistros {
				resolvedDistroMap[int64(d.ID)] = d
			}
		case config == AnyOSSpecified:
			// TODO: one enhancement we may want to do later is "has OS defined but is not specific" which this does NOT cover. This is "may or may not have an OS defined" which is different.
			hasAny = true
		case *config == *NoOSSpecified:
			hasNone = true
		}
	}

	if (hasAny || hasNone) && hasSpecific {
		return nil, fmt.Errorf("cannot mix specific distro with any or none distro specifiers")
	}

	var resolvedDistros []OperatingSystem
	switch {
	case hasAny:
		return query, nil
	case hasNone:
		return query.Where("operating_system_id IS NULL"), nil
	case hasSpecific:
		for _, d := range resolvedDistroMap {
			resolvedDistros = append(resolvedDistros, d)
		}
		sort.Slice(resolvedDistros, func(i, j int) bool {
			return resolvedDistros[i].ID < resolvedDistros[j].ID
		})
	}

	query = query.Joins("JOIN operating_systems ON affected_package_handles.operating_system_id = operating_systems.id")

	if len(resolvedDistros) > 0 {
		ids := make([]ID, len(resolvedDistros))
		for i, d := range resolvedDistros {
			ids[i] = d.ID
		}
		query = query.Where("operating_systems.id IN ?", ids)
	}

	return query, nil
}

func (s *affectedPackageStore) resolveDistro(d OSSpecifier) ([]OperatingSystem, error) {
	if d.Name == "" && d.LabelVersion == "" {
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
		query = query.Where("name = ? OR release_id = ?", d.Name, d.Name)
	}

	if d.LabelVersion != "" {
		query = query.Where("codename = ? OR label_version = ?", d.LabelVersion, d.LabelVersion)
	}

	return s.searchForDistroVersionVariants(query, d)
}

func (s *affectedPackageStore) searchForDistroVersionVariants(query *gorm.DB, d OSSpecifier) ([]OperatingSystem, error) {
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

func (s *affectedPackageStore) applyAlias(d *OSSpecifier) error {
	if d.Name == "" {
		return nil
	}

	var aliases []OperatingSystemAlias
	err := s.db.Where("alias = ?", d.Name).Find(&aliases).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to resolve alias for distro %q: %w", d.Name, err)
		}
		return nil
	}

	var alias *OperatingSystemAlias

	for _, a := range aliases {
		if a.Codename != "" && a.Codename != d.LabelVersion {
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

func (s *affectedPackageStore) handlePreload(query *gorm.DB, config GetAffectedPackageOptions) *gorm.DB {
	var limitArgs []interface{}
	if config.Limit > 0 {
		query = query.Limit(config.Limit)
		limitArgs = append(limitArgs, func(db *gorm.DB) *gorm.DB {
			return db.Limit(config.Limit)
		})
	}

	if config.PreloadPackage {
		query = query.Preload("Package", limitArgs...)

		if config.PreloadPackageCPEs {
			query = query.Preload("Package.CPEs", limitArgs...)
		}
	}

	if config.PreloadVulnerability {
		query = query.Preload("Vulnerability", limitArgs...).Preload("Vulnerability.Provider", limitArgs...)
	}

	if config.PreloadOS {
		query = query.Preload("OperatingSystem", limitArgs...)
	}

	return query
}

func handleCPEOptions(query *gorm.DB, c *cpe.Attributes) *gorm.DB {
	if c.Part != cpe.Any {
		query = query.Where("cpes.part = ?", c.Part)
	}

	if c.Vendor != cpe.Any {
		query = query.Where("cpes.vendor = ?", c.Vendor)
	}

	if c.Product != cpe.Any {
		query = query.Where("cpes.product = ?", c.Product)
	}

	if c.Edition != cpe.Any {
		query = query.Where("cpes.edition = ?", c.Edition)
	}

	if c.Language != cpe.Any {
		query = query.Where("cpes.language = ?", c.Language)
	}

	if c.SWEdition != cpe.Any {
		query = query.Where("cpes.sw_edition = ?", c.SWEdition)
	}

	if c.TargetSW != cpe.Any {
		query = query.Where("cpes.target_sw = ?", c.TargetSW)
	}

	if c.TargetHW != cpe.Any {
		query = query.Where("cpes.target_hw = ?", c.TargetHW)
	}

	if c.Other != cpe.Any {
		query = query.Where("cpes.other = ?", c.Other)
	}
	return query
}

func hasDistroSpecified(d *OSSpecifier) bool {
	if d == AnyOSSpecified {
		return false
	}

	if *d == *NoOSSpecified {
		return false
	}
	return true
}
