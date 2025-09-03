package v6

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/cpe"
)

const (
	anyPkg = "any"
	anyOS  = "any"
)

var NoOSSpecified = &OSSpecifier{}
var AnyOSSpecified *OSSpecifier
var AnyPackageSpecified *PackageSpecifier
var ErrMissingOSIdentification = errors.New("missing OS name or codename")
var ErrOSNotPresent = errors.New("OS not present")
var ErrLimitReached = errors.New("query limit reached")

type GetPackageOptions struct {
	PreloadOS             bool
	PreloadPackage        bool
	PreloadPackageCPEs    bool
	PreloadVulnerability  bool
	PreloadBlob           bool
	OSs                   OSSpecifiers
	Vulnerabilities       VulnerabilitySpecifiers
	AllowBroadCPEMatching bool
	Limit                 int
}

type PackageSpecifiers []*PackageSpecifier

type PackageSpecifier struct {
	Name      string
	Ecosystem string
	CPE       *cpe.Attributes
}

func (p *PackageSpecifier) String() string {
	if p == nil {
		return anyPkg
	}

	var args []string
	if p.Name != "" {
		args = append(args, fmt.Sprintf("name=%s", p.Name))
	}

	if p.Ecosystem != "" {
		args = append(args, fmt.Sprintf("ecosystem=%s", p.Ecosystem))
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

type packageHandleStore interface {
	*AffectedPackageHandle | *UnaffectedPackageHandle
}

type packageHandleAccessor interface {
	getPackageHandle() *packageHandle
}

type packageStore struct {
	db        *gorm.DB
	blobStore *blobStore
	osStore   *operatingSystemStore
}

func newPackageStore(db *gorm.DB, bs *blobStore, oss *operatingSystemStore) *packageStore {
	return &packageStore{
		db:        db,
		blobStore: bs,
		osStore:   oss,
	}
}

func addPackages[T packageHandleStore](s *packageStore, packages ...T) (bool, error) {
	cacheInst, ok := cacheFromContext(s.db.Statement.Context)
	if !ok {
		return false, fmt.Errorf("unable to fetch package cache from context")
	}

	var final []*Package
	var hasCPEs bool
	byCacheKey := make(map[string][]*Package)

	for _, p := range packages {
		// convert to packageHandle to access fields
		ph := any(p).(packageHandleAccessor).getPackageHandle()

		if ph.Package != nil {
			if len(ph.Package.CPEs) > 0 {
				// never use the cache if there are CPEs involved
				final = append(final, ph.Package)
				hasCPEs = true
				continue
			}
			key := ph.Package.cacheKey()
			if existingID, ok := cacheInst.getID(ph.Package); ok {
				// seen in a previous transaction...
				ph.PackageID = existingID
			} else if _, ok := byCacheKey[key]; !ok {
				// not seen within this transaction
				final = append(final, ph.Package)
			}
			byCacheKey[key] = append(byCacheKey[key], ph.Package)
		}
	}

	if len(final) == 0 {
		return false, nil
	}

	// since there is risk of needing to write through packages with conflicting CPEs we cannot write these in batches,
	// and since the before hooks reason about previous entries within this loop (potentially) we must ensure that
	// these are written in different transactions.
	for _, p := range final {
		if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(p).Error; err != nil {
			return false, fmt.Errorf("unable to create package records: %w", err)
		}
	}

	// update the cache with the new records
	for _, r := range final {
		cacheInst.set(r)
	}

	// update all references with the IDs from the cache
	for _, refs := range byCacheKey {
		for _, r := range refs {
			id, ok := cacheInst.getID(r)
			if ok {
				r.setRowID(id)
			}
		}
	}

	// update the parent objects with the FK ID
	for _, p := range packages {
		ph := any(p).(packageHandleAccessor).getPackageHandle()
		if ph.Package != nil {
			ph.PackageID = ph.Package.ID
		}
	}
	return hasCPEs, nil
}

func addPackagesWithOS[T packageHandleStore](s *packageStore, packages ...T) error {
	for _, p := range packages {
		ph := any(p).(packageHandleAccessor).getPackageHandle()
		if err := s.osStore.addOsFromPackages(ph); err != nil {
			return fmt.Errorf("unable to add package OS: %w", err)
		}
	}

	hasCpes, err := addPackages(s, packages...)
	if err != nil {
		return fmt.Errorf("unable to add packages: %w", err)
	}

	omit := []string{"OperatingSystem"}
	if !hasCpes {
		omit = append(omit, "Package")
	}

	for _, v := range packages {
		if err := s.blobStore.addBlobable(any(v).(blobable)); err != nil {
			return fmt.Errorf("unable to add blob: %w", err)
		}

		if err := s.db.Omit(omit...).Create(v).Error; err != nil {
			return err
		}
	}
	return nil
}

func getPackages[T packageHandleStore]( //nolint:funlen
	s *packageStore,
	pkg *PackageSpecifier,
	config *GetPackageOptions,
	tableName string,
) ([]T, error) {
	if config == nil {
		config = &GetPackageOptions{}
	}

	start := time.Now()
	count := 0
	defer func() {
		log.
			WithFields(
				"pkg", pkg.String(),
				"distro", config.OSs,
				"vulns", config.Vulnerabilities,
				"duration", time.Since(start),
				"records", count,
			).
			Trace("fetched package record")
	}()

	query := s.handlePackage(s.db.Table(tableName), pkg, config.AllowBroadCPEMatching)

	var err error
	query, err = s.handleVulnerabilityOptions(query, config.Vulnerabilities, tableName)
	if err != nil {
		return nil, err
	}

	query, err = s.handleOSOptions(query, config.OSs, tableName)
	if err != nil {
		return nil, err
	}

	query = s.handlePreload(query, *config)

	var models []T
	var results []T

	if err := query.FindInBatches(&results, batchSize, func(_ *gorm.DB, _ int) error {
		if config.PreloadBlob {
			var blobs []blobable
			for _, r := range results {
				blobs = append(blobs, any(r).(blobable))
			}
			if err := s.blobStore.attachBlobValue(blobs...); err != nil {
				return fmt.Errorf("unable to attach package blobs: %w", err)
			}
		}

		if config.PreloadVulnerability {
			var vulns []blobable
			for _, r := range results {
				ph := any(r).(packageHandleAccessor).getPackageHandle()
				if ph.Vulnerability != nil {
					vulns = append(vulns, ph.Vulnerability)
				}
			}
			if err := s.blobStore.attachBlobValue(vulns...); err != nil {
				return fmt.Errorf("unable to attach vulnerability blob: %w", err)
			}
		}

		models = append(models, results...)

		count += len(results)

		if config.Limit > 0 && len(models) >= config.Limit {
			return ErrLimitReached
		}

		return nil
	}).Error; err != nil {
		return models, fmt.Errorf("unable to fetch package records: %w", err)
	}

	return models, nil
}

func (s *packageStore) handlePackage(query *gorm.DB, p *PackageSpecifier, allowBroad bool) *gorm.DB {
	if p == nil {
		return query
	}

	if err := s.applyPackageAlias(p); err != nil {
		log.Errorf("failed to apply package alias: %v", err)
	}

	// Get table name from the query
	tableName := query.Statement.Table
	query = query.Joins(fmt.Sprintf("JOIN packages ON %s.package_id = packages.id", tableName))

	if p.Name != "" {
		query = query.Where("packages.name = ? collate nocase", p.Name)
	}
	if p.Ecosystem != "" {
		query = query.Where("packages.ecosystem = ? collate nocase", p.Ecosystem)
	}

	if p.CPE != nil {
		query = query.Joins("JOIN package_cpes ON packages.id = package_cpes.package_id")
		query = query.Joins("JOIN cpes ON package_cpes.cpe_id = cpes.id")
		query = handleCPEOptions(query, p.CPE, allowBroad)
	}

	return query
}

func (s *packageStore) handleVulnerabilityOptions(query *gorm.DB, configs []VulnerabilitySpecifier, tableName string) (*gorm.DB, error) {
	if len(configs) == 0 {
		return query, nil
	}
	query = query.Joins(fmt.Sprintf("JOIN vulnerability_handles ON %s.vulnerability_id = vulnerability_handles.id", tableName))

	return handleVulnerabilityOptions(s.db, query, configs...)
}

func (s *packageStore) handleOSOptions(query *gorm.DB, configs []*OSSpecifier, tableName string) (*gorm.DB, error) {
	ids := map[int64]struct{}{}

	if len(configs) == 0 {
		configs = append(configs, AnyOSSpecified)
	}

	var hasAny, hasNone, hasSpecific bool
	// process OS specs...
	for _, config := range configs {
		switch {
		case hasOSSpecified(config):
			curResolved, err := s.osStore.GetOperatingSystems(*config)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve operating system: %w", err)
			}

			hasSpecific = true
			for _, d := range curResolved {
				ids[int64(d.ID)] = struct{}{}
			}
		case config == AnyOSSpecified:
			hasAny = true
		case *config == *NoOSSpecified:
			hasNone = true
		}
	}

	if (hasAny || hasNone) && hasSpecific {
		return nil, fmt.Errorf("cannot mix specific OS with 'any' or 'none' OS specifiers")
	}

	switch {
	case hasAny:
		return query, nil
	case hasNone:
		return query.Where("operating_system_id IS NULL"), nil
	}

	// we were told to filter by specific OSes but found no matching OSes...
	if len(ids) == 0 {
		return nil, ErrOSNotPresent
	}

	query = query.Where(fmt.Sprintf("%s.operating_system_id IN ?", tableName), maps.Keys(ids))

	return query, nil
}

// Keep the original helper methods unchanged
func (s *packageStore) applyPackageAlias(d *PackageSpecifier) error {
	if d.Ecosystem == "" {
		return nil
	}

	// only ecosystem replacement is supported today
	var aliases []PackageSpecifierOverride
	err := s.db.Where("ecosystem = ? collate nocase", d.Ecosystem).Find(&aliases).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to resolve alias for distro %q: %w", d.Name, err)
		}
		return nil
	}

	var alias *PackageSpecifierOverride

	for _, a := range aliases {
		if a.Ecosystem == "" {
			continue
		}

		alias = &a
		break
	}

	if alias == nil {
		return nil
	}

	if alias.ReplacementEcosystem != nil {
		d.Ecosystem = *alias.ReplacementEcosystem
	}

	return nil
}

func (s *packageStore) handlePreload(query *gorm.DB, config GetPackageOptions) *gorm.DB {
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

func handleCPEOptions(query *gorm.DB, c *cpe.Attributes, allowBroad bool) *gorm.DB {
	query = queryCPEAttributeScope(query, c.Part, "cpes.part", allowBroad)
	query = queryCPEAttributeScope(query, c.Vendor, "cpes.vendor", allowBroad)
	query = queryCPEAttributeScope(query, c.Product, "cpes.product", allowBroad)
	query = queryCPEAttributeScope(query, c.Edition, "cpes.edition", allowBroad)
	query = queryCPEAttributeScope(query, c.Language, "cpes.language", allowBroad)
	query = queryCPEAttributeScope(query, c.SWEdition, "cpes.software_edition", allowBroad)
	query = queryCPEAttributeScope(query, c.TargetSW, "cpes.target_software", allowBroad)
	query = queryCPEAttributeScope(query, c.TargetHW, "cpes.target_hardware", allowBroad)
	query = queryCPEAttributeScope(query, c.Other, "cpes.other", allowBroad)
	return query
}

func queryCPEAttributeScope(query *gorm.DB, value string, dbColumn string, allowBroad bool) *gorm.DB {
	if value == cpe.Any {
		return query
	}
	if allowBroad {
		// this allows for a package that specifies a CPE like
		//
		//   'cpe:2.3:a:cloudflare:octorpki:1.4.1:*:*:*:*:golang:*:*'
		//
		// to be able to positively match with a package CPE that claims to match "any" target software.
		//
		//   'cpe:2.3:a:cloudflare:octorpki:1.4.1:*:*:*:*:*:*:*'
		//
		// practically speaking, how would a vulnerability provider know that the package is vulnerable for all
		// target software values (against the universe of packaging) -- this isn't practical.
		return query.Where(fmt.Sprintf("%s = ? collate nocase or %s = ? collate nocase", dbColumn, dbColumn), value, cpe.Any)
	}
	// this is the most practical use case, where the package CPE with specified values must match the vulnerability
	// CPE exactly (only for specified fields)
	return query.Where(fmt.Sprintf("%s = ? collate nocase", dbColumn), value)
}

func hasOSSpecified(d *OSSpecifier) bool {
	if d == AnyOSSpecified {
		return false
	}

	if *d == *NoOSSpecified {
		return false
	}
	return true
}
