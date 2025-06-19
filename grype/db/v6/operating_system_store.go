package v6

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/version"
	"regexp"
	"strings"

	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
)

type OSSpecifiers []*OSSpecifier

type OSRangeSpecifiers []OSRangeSpecifier

// OSSpecifier is a struct that represents a distro in a way that can be used to query the affected package store.
type OSSpecifier struct {
	// Name of the distro as identified by the ID field in /etc/os-release (or similar normalized name, e.g. "oracle" instead of "ol")
	Name string

	// MajorVersion is the first field in the VERSION_ID field in /etc/os-release (e.g. 7 in "7.0.1406")
	MajorVersion string

	// MinorVersion is the second field in the VERSION_ID field in /etc/os-release (e.g. 0 in "7.0.1406")
	MinorVersion string

	// RemainingVersion is anything after the minor version in the VERSION_ID field in /etc/os-release (e.g. 1406 in "7.0.1406")
	RemainingVersion string

	// LabelVersion is a string that represents a floating version (e.g. "edge" or "unstable") or is the CODENAME field in /etc/os-release (e.g. "wheezy" for debian 7)
	LabelVersion string

	// Variant is a string that represents a variant of the distro (e.g. "eus" for RHEL EUS releases)
	Variant string
}

type OSRangeSpecifier struct {
	// Name of the distro as identified by the ID field in /etc/os-release (or similar normalized name, e.g. "oracle" instead of "ol")
	Name string

	Ranges []OSVersionRange

	// Variant is a string that represents a variant of the distro (e.g. "eus" for RHEL EUS releases)
	Variant string
}

type OSVersionRange struct {
	// MajorVersion is the first field in the VERSION_ID field in /etc/os-release (e.g. 7 in "7.0.1406")
	MajorVersion string

	// MinorVersion is the second field in the VERSION_ID field in /etc/os-release (e.g. 0 in "7.0.1406")
	MinorVersion string

	// RemainingVersion is anything after the minor version in the VERSION_ID field in /etc/os-release (e.g. 1406 in "7.0.1406")
	RemainingVersion string

	// LabelVersion is a string that represents a floating version (e.g. "edge" or "unstable") or is the CODENAME field in /etc/os-release (e.g. "wheezy" for debian 7)
	LabelVersion string

	Operator version.Operator
}

func (r *OSRangeSpecifier) expression() string {
	if len(r.Ranges) == 0 {
		return ""
	}

	var parts []string
	for _, v := range r.Ranges {
		if v.MajorVersion != "" {
			part := v.MajorVersion
			if v.MinorVersion != "" {
				part += "." + v.MinorVersion
				if v.RemainingVersion != "" {
					part += "." + v.RemainingVersion
				}
			}
			parts = append(parts, string(v.Operator)+part)
		} else if v.LabelVersion != "" {
			parts = append(parts, string(v.Operator)+v.LabelVersion)
		}
	}

	return strings.Join(parts, ",")
}

func (d *OSSpecifier) clean() {
	d.MajorVersion = trimZeroes(d.MajorVersion)
	d.MinorVersion = trimZeroes(d.MinorVersion)
}

func (d *OSSpecifier) String() string {
	if d == nil {
		return anyOS
	}

	if *d == *NoOSSpecified {
		return "none"
	}

	var ver string
	if d.MajorVersion != "" {
		ver = d.version()
	} else {
		ver = d.LabelVersion
	}

	distroDisplayName := d.Name
	if ver != "" {
		distroDisplayName += "@" + ver
	}
	if ver == d.MajorVersion && d.LabelVersion != "" {
		distroDisplayName += " (" + d.LabelVersion + ")"
	}

	return distroDisplayName
}

func (d OSSpecifier) version() string {
	if d.MajorVersion != "" {
		if d.MinorVersion != "" {
			if d.RemainingVersion != "" {
				return d.MajorVersion + "." + d.MinorVersion + "." + d.RemainingVersion
			}
			return d.MajorVersion + "." + d.MinorVersion
		}
		return d.MajorVersion
	}

	return d.LabelVersion
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

type OperatingSystemStoreReader interface {
	GetOperatingSystems(OSSpecifier) ([]OperatingSystem, error)
	GetOperatingSystemsInRange(dr OSRangeSpecifier) ([]OperatingSystem, error)
}

type operatingSystemStore struct {
	db        *gorm.DB
	blobStore *blobStore
}

func newOperatingSystemStore(db *gorm.DB, bs *blobStore) *operatingSystemStore {
	return &operatingSystemStore{
		db:        db,
		blobStore: bs,
	}
}

func (s *operatingSystemStore) addOsFromPackages(packages ...*AffectedPackageHandle) error { // nolint:dupl
	cacheInst, ok := cacheFromContext(s.db.Statement.Context)
	if !ok {
		return fmt.Errorf("unable to fetch OS cache from context")
	}

	var final []*OperatingSystem
	byCacheKey := make(map[string][]*OperatingSystem)
	for _, p := range packages {
		if p.OperatingSystem != nil {
			p.OperatingSystem.clean()
			key := p.OperatingSystem.cacheKey()
			if existingID, ok := cacheInst.getID(p.OperatingSystem); ok {
				// seen in a previous transaction...
				p.OperatingSystemID = &existingID
			} else if _, ok := byCacheKey[key]; !ok {
				// not seen within this transaction
				final = append(final, p.OperatingSystem)
			}
			byCacheKey[key] = append(byCacheKey[key], p.OperatingSystem)
		}
	}

	if len(final) == 0 {
		return nil
	}

	if err := s.db.Create(final).Error; err != nil {
		return fmt.Errorf("unable to create OS records: %w", err)
	}

	// update the cache with the new records
	for _, ref := range final {
		cacheInst.set(ref)
	}

	// update all references with the IDs from the cache
	for _, refs := range byCacheKey {
		for _, ref := range refs {
			id, ok := cacheInst.getID(ref)
			if ok {
				ref.setRowID(id)
			}
		}
	}

	// update the parent objects with the FK ID
	for _, p := range packages {
		if p.OperatingSystem != nil {
			p.OperatingSystemID = &p.OperatingSystem.ID
		}
	}
	return nil
}

func (s *operatingSystemStore) GetOperatingSystemsInRange(dr OSRangeSpecifier) ([]OperatingSystem, error) {
	switch len(dr.Ranges) {
	case 0:
		return nil, fmt.Errorf("no ranges specified for OS %q", dr.Name)
	case 1, 2:
		break // ok, we can handle 1 or 2 ranges
	default:
		return nil, fmt.Errorf("too many ranges specified for OS %q: %d", dr.Name, len(dr.Ranges))
	}

	// create an os specifier for each part of the range
	var ds []OSSpecifier
	var name string
	for i, r := range dr.Ranges {
		if dr.Name == "" && r.LabelVersion == "" {
			return nil, ErrMissingOSIdentification
		}

		d := OSSpecifier{
			Name:             dr.Name,
			MajorVersion:     r.MajorVersion,
			MinorVersion:     r.MinorVersion,
			RemainingVersion: r.RemainingVersion,
			LabelVersion:     r.LabelVersion,
			Variant:          dr.Variant,
		}

		// search for aliases for the given distro; we intentionally map some OSs to other OSs in terms of
		// vulnerability (e.g. `centos` is an alias for `rhel`). If an alias is found always use that alias in
		// searches (there will never be anything in the DB for aliased distros).
		if err := s.applyOSAlias(&d); err != nil {
			return nil, err
		}

		if d.MajorVersion == "" {
			return nil, fmt.Errorf("numeric version is required to select on OS ranges for %q", d.Name)
		}

		if d.Name == "" {
			return nil, ErrMissingOSIdentification
		}

		if name == "" {
			name = d.Name
		}

		d.clean()
		ds = append(ds, d)

		// we preserve any alias transformations that were applied to the OS specifier when we later build an expression
		dr.Ranges[i] = OSVersionRange{
			MajorVersion:     d.MajorVersion,
			MinorVersion:     d.MinorVersion,
			RemainingVersion: d.RemainingVersion,
			LabelVersion:     d.LabelVersion,
			Operator:         r.Operator,
		}
	}

	dWithoutVersion := OSSpecifier{
		Name:    name, // we want to use the name after performing any alias transformations
		Variant: dr.Variant,
	}

	allOS, err := s.GetOperatingSystems(dWithoutVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get OS by name %q: %w", dWithoutVersion.Name, err)
	}

	// we treat the set of os specifiers as an AND'd set (not OR'd as dealt with in the vulnerability provider)
	expression := dr.expression()
	constraint, err := version.GetConstraint(dr.expression(), version.SemanticFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OS version range expression %q: %w", expression, err)
	}

	var result []OperatingSystem
	for _, os := range allOS {
		ver := version.NewVersion(os.Version(), version.SemanticFormat)
		if ver == nil {
			// TODO: log?
			continue
		}
		satisfied, err := constraint.Satisfied(ver)
		if err != nil {
			// TODO: log?
			continue
		}
		if satisfied {
			result = append(result, os)
		}
	}
	return result, nil
}

func (s *operatingSystemStore) prepareQuery(d OSSpecifier) (*gorm.DB, error) {
	query := s.db.Model(&OperatingSystem{})

	if d.Name != "" {
		query = query.Where("name = ? collate nocase OR release_id = ? collate nocase", d.Name, d.Name)
	}

	if d.LabelVersion != "" {
		query = query.Where("codename = ? collate nocase OR label_version = ? collate nocase", d.LabelVersion, d.LabelVersion)
	}

	if d.Variant != "" {
		query = query.Where("variant = ? collate nocase", d.Variant)
	} else {
		// we specifically want to match vanilla...
		query = query.Where("variant IS NULL OR variant = ''")
	}
	return query, nil
}

func (s *operatingSystemStore) GetOperatingSystems(d OSSpecifier) ([]OperatingSystem, error) {
	if d.Name == "" && d.LabelVersion == "" {
		return nil, ErrMissingOSIdentification
	}

	// search for aliases for the given distro; we intentionally map some OSs to other OSs in terms of
	// vulnerability (e.g. `centos` is an alias for `rhel`). If an alias is found always use that alias in
	// searches (there will never be anything in the DB for aliased distros).
	if err := s.applyOSAlias(&d); err != nil {
		return nil, err
	}

	d.clean()

	query, err := s.prepareQuery(d)
	if err != nil {
		return nil, err
	}
	return s.searchForOSExactVersions(query, d)
}

func (s *operatingSystemStore) applyOSAlias(d *OSSpecifier) error {
	if d.Name == "" {
		return nil
	}

	var aliases []OperatingSystemSpecifierOverride
	err := s.db.Where("alias = ? collate nocase", d.Name).Find(&aliases).Error
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("failed to resolve alias for distro %q: %w", d.Name, err)
		}
		return nil
	}

	var alias *OperatingSystemSpecifierOverride

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

func (s *operatingSystemStore) searchForOSExactVersions(query *gorm.DB, d OSSpecifier) ([]OperatingSystem, error) {
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
