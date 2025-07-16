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

	// Channel is a string that represents a different feed for fix and vulnerability data (e.g. "eus" for RHEL)
	Channel string
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
}

type operatingSystemStore struct {
	db            *gorm.DB
	blobStore     *blobStore
	clientVersion *version.Version
}

func newOperatingSystemStore(db *gorm.DB, bs *blobStore) *operatingSystemStore {
	return &operatingSystemStore{
		db:            db,
		blobStore:     bs,
		clientVersion: version.New(fmt.Sprintf("%d.%d.%d", ModelVersion, Revision, Addition), version.SemanticFormat),
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

	// handle non-version fields
	query := s.prepareQuery(d)

	// handle version-like fields
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
		if a.DBVersionConstraint != "" {
			c, err := version.GetConstraint(a.DBVersionConstraint, version.SemanticFormat)
			if err != nil {
				log.Debugf("failed to parse version constraint %q for OS alias %#v: %v", a.DBVersionConstraint, a, err)
				continue
			}

			ok, err := c.Satisfied(s.clientVersion)
			if err != nil {
				log.Debugf("failed to check version constraint %q for OS alias %#v: %v", a.DBVersionConstraint, a, err)
				continue
			}

			if !ok {
				// explicitly told that this override does not apply to this client version
				continue
			}
		}

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

func (s *operatingSystemStore) prepareQuery(d OSSpecifier) *gorm.DB {
	query := s.db.Model(&OperatingSystem{})

	if d.Name != "" {
		query = query.Where("name = ? collate nocase OR release_id = ? collate nocase", d.Name, d.Name)
	}

	if d.LabelVersion != "" {
		query = query.Where("codename = ? collate nocase OR label_version = ? collate nocase", d.LabelVersion, d.LabelVersion)
	}

	if d.Channel != "" {
		query = query.Where("channel = ? collate nocase", d.Channel)
	} else {
		// we specifically want to match vanilla...
		query = query.Where("channel IS NULL OR channel = ''")
	}
	return query
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

func trimZeroes(s string) string {
	// trim leading zeros from the version components
	if s == "" {
		return s
	}
	if s[0] == '0' {
		s = strings.TrimLeft(s, "0")
	}
	if s == "" {
		// we've not only trimmed leading zeros, but also the entire string
		// we should preserve the zero value for the version
		return "0"
	}
	return s
}
