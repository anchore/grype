package v6

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/OneOfOne/xxhash"
	"gorm.io/gorm"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/grype/internal/schemaver"
)

func Models() []any {
	return []any{
		// core data store
		&Blob{},

		// non-domain info
		&DBMetadata{},

		// data source info
		&Provider{},

		// vulnerability related search tables
		&VulnerabilityHandle{},
		&VulnerabilityAlias{},

		// package related search tables
		&AffectedPackageHandle{}, // join on package, operating system
		&OperatingSystem{},
		&OperatingSystemSpecifierOverride{},
		&Package{},
		&PackageSpecifierOverride{},

		// CPE related search tables
		&AffectedCPEHandle{}, // join on CPE
		&Cpe{},

		// decorations to vulnerability records
		&KnownExploitedVulnerabilityHandle{},
		&EpssHandle{},
		&EpssMetadata{},
	}
}

type ID int64

// core data store //////////////////////////////////////////////////////

type Blob struct {
	ID    ID     `gorm:"column:id;primaryKey"`
	Value string `gorm:"column:value;not null"`
}

func (b Blob) computeDigest() string {
	h := xxhash.New64()
	if _, err := h.Write([]byte(b.Value)); err != nil {
		log.Errorf("unable to hash blob: %v", err)
		panic(err)
	}
	return fmt.Sprintf("xxh64:%x", h.Sum(nil))
}

// non-domain info //////////////////////////////////////////////////////

type DBMetadata struct {
	BuildTimestamp *time.Time `gorm:"column:build_timestamp;not null"`
	Model          int        `gorm:"column:model;not null"`
	Revision       int        `gorm:"column:revision;not null"`
	Addition       int        `gorm:"column:addition;not null"`
}

func newSchemaVerFromDBMetadata(m DBMetadata) schemaver.SchemaVer {
	return schemaver.New(m.Model, m.Revision, m.Addition)
}

// data source info //////////////////////////////////////////////////////

// Provider is the upstream data processor (usually Vunnel) that is responsible for vulnerability records. Each provider
// should be scoped to a specific vulnerability dataset, for instance, the "ubuntu" provider for all records from
// Canonicals' Ubuntu Security Notices (for all Ubuntu distro versions).
type Provider struct {
	// ID of the Vunnel provider (or sub processor responsible for data records from a single specific source, e.g. "ubuntu")
	ID string `gorm:"column:id;primaryKey"`

	// Version of the Vunnel provider (or sub processor equivalent)
	Version string `gorm:"column:version"`

	// Processor is the name of the application that processed the data (e.g. "vunnel")
	Processor string `gorm:"column:processor"`

	// DateCaptured is the timestamp which the upstream data was pulled and processed
	DateCaptured *time.Time `gorm:"column:date_captured"`

	// InputDigest is a self describing hash (e.g. sha256:123... not 123...) of all data used by the provider to generate the vulnerability records
	InputDigest string `gorm:"column:input_digest"`
}

func (p *Provider) String() string {
	if p == nil {
		return ""
	}
	date := "?"
	if p.DateCaptured != nil {
		date = p.DateCaptured.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s@v%s from %s using %q at %s", p.ID, p.Version, p.Processor, p.InputDigest, date)
}

func (p *Provider) cacheKey() string {
	return strings.ToLower(p.String())
}

func (p *Provider) tableName() string {
	return cpesTableCacheKey
}

func (p *Provider) rowID() string {
	return p.ID
}

func (p *Provider) setRowID(i string) {
	p.ID = i
}

func (p *Provider) BeforeCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		if existingID, ok := cacheInst.getString(p); ok {
			p.setRowID(existingID)
		}
		return nil
	}
	return fmt.Errorf("provider creation is not supported")
}

func (p *Provider) AfterCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		cacheInst.set(p)
	}
	return nil
}

// vulnerability related search tables //////////////////////////////////////////////////////

// VulnerabilityHandle represents the pointer to the core advisory record for a single known vulnerability from a specific provider.
type VulnerabilityHandle struct {
	ID ID `gorm:"column:id;primaryKey"`

	// Name is the unique name for the vulnerability (same as the decoded VulnerabilityBlob.ID)
	Name string `gorm:"column:name;not null;index,collate:NOCASE"`

	// Status conveys the actionability of the current record (one of "active", "analyzing", "rejected", "disputed")
	Status VulnerabilityStatus `gorm:"column:status;not null;index,collate:NOCASE"`

	// PublishedDate is the date the vulnerability record was first published
	PublishedDate *time.Time `gorm:"column:published_date;index"`

	// ModifiedDate is the date the vulnerability record was last modified
	ModifiedDate *time.Time `gorm:"column:modified_date;index"`

	// WithdrawnDate is the date the vulnerability record was withdrawn
	WithdrawnDate *time.Time `gorm:"column:withdrawn_date;index"`

	ProviderID string    `gorm:"column:provider_id;not null;index"`
	Provider   *Provider `gorm:"foreignKey:ProviderID"`

	BlobID    ID                 `gorm:"column:blob_id;index,unique"`
	BlobValue *VulnerabilityBlob `gorm:"-"`
}

func (v VulnerabilityHandle) String() string {
	return fmt.Sprintf("%s/%s", v.Provider, v.Name)
}

func (v VulnerabilityHandle) getBlobValue() any {
	if v.BlobValue == nil {
		return nil // must return untyped nil or getBlobValue() == nil will always be false
	}
	return v.BlobValue
}

func (v *VulnerabilityHandle) setBlobID(id ID) {
	v.BlobID = id
}

func (v VulnerabilityHandle) getBlobID() ID {
	return v.BlobID
}

func (v *VulnerabilityHandle) setBlob(rawBlobValue []byte) error {
	var blobValue VulnerabilityBlob
	if err := json.Unmarshal(rawBlobValue, &blobValue); err != nil {
		return fmt.Errorf("unable to unmarshal vulnerability blob value: %w", err)
	}

	v.BlobValue = &blobValue
	return nil
}

func (v *VulnerabilityHandle) cacheKey() string {
	provider := "none"
	if v.Provider != nil {
		provider = v.Provider.ID
	}
	return strings.ToLower(fmt.Sprintf("%s from %s with %d", v.Name, provider, v.BlobID))
}

func (v *VulnerabilityHandle) rowID() ID {
	return v.ID
}

func (v *VulnerabilityHandle) tableName() string {
	return vulnerabilitiesTableCacheKey
}

func (v *VulnerabilityHandle) setRowID(i ID) {
	v.ID = i
}

func (v *VulnerabilityHandle) BeforeCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		if existing, ok := cacheInst.getID(v); ok {
			v.setRowID(existing)
		}

		return nil
	}

	return fmt.Errorf("vulnerability creation is not supported")
}

func (v *VulnerabilityHandle) AfterCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		cacheInst.set(v)
	}
	return nil
}

type VulnerabilityAlias struct {
	// Name is the unique name for the vulnerability
	Name string `gorm:"column:name;primaryKey;index,collate:NOCASE"`

	// Alias is an alternative name for the vulnerability that must be upstream from the Name (e.g if name is "RHSA-1234" then the upstream could be "CVE-1234-5678", but not the other way around)
	Alias string `gorm:"column:alias;primaryKey;index,collate:NOCASE;not null"`
}

// package related search tables //////////////////////////////////////////////////////

// AffectedPackageHandle represents a single package affected by the specified vulnerability. A package here is a
// name within a known ecosystem, such as "python" or "golang". It is important to note that this table relates
// vulnerabilities to resolved packages. There are cases when we have package identifiers but are not resolved to
// packages; for example, when we have a CPE but not a clear understanding of the package ecosystem and authoritative
// name (which might or might not be the product name in the CPE), in which case AffectedCPEHandle should be used.
type AffectedPackageHandle struct {
	ID              ID                   `gorm:"column:id;primaryKey"`
	VulnerabilityID ID                   `gorm:"column:vulnerability_id;index;not null"`
	Vulnerability   *VulnerabilityHandle `gorm:"foreignKey:VulnerabilityID"`

	OperatingSystemID *ID              `gorm:"column:operating_system_id;index"`
	OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`

	PackageID ID       `gorm:"column:package_id;index"`
	Package   *Package `gorm:"foreignKey:PackageID"`

	BlobID    ID                   `gorm:"column:blob_id"`
	BlobValue *AffectedPackageBlob `gorm:"-"`
}

func (aph AffectedPackageHandle) vulnerability() string {
	if aph.Vulnerability != nil {
		return aph.Vulnerability.Name
	}
	if aph.BlobValue != nil {
		if len(aph.BlobValue.CVEs) > 0 {
			return aph.BlobValue.CVEs[0]
		}
	}
	return ""
}

func (aph AffectedPackageHandle) String() string {
	var fields []string

	if aph.BlobValue != nil {
		v := aph.BlobValue.String()
		if v != "" {
			fields = append(fields, v)
		}
	}
	if aph.OperatingSystem != nil {
		fields = append(fields, fmt.Sprintf("os=%q", aph.OperatingSystem.String()))
	} else {
		fields = append(fields, fmt.Sprintf("os=%d", aph.OperatingSystemID))
	}

	if aph.Package != nil {
		fields = append(fields, fmt.Sprintf("pkg=%q", aph.Package.String()))
	} else {
		fields = append(fields, fmt.Sprintf("pkg=%d", aph.PackageID))
	}

	if aph.Vulnerability != nil {
		fields = append(fields, fmt.Sprintf("vuln=%q", aph.Vulnerability.String()))
	} else {
		fields = append(fields, fmt.Sprintf("vuln=%d", aph.VulnerabilityID))
	}

	return fmt.Sprintf("affectedPackage(%s)", strings.Join(fields, ", "))
}

func (aph AffectedPackageHandle) getBlobValue() any {
	if aph.BlobValue == nil {
		return nil // must return untyped nil or getBlobValue() == nil will always be false
	}
	return aph.BlobValue
}

func (aph *AffectedPackageHandle) setBlobID(id ID) {
	aph.BlobID = id
}

func (aph AffectedPackageHandle) getBlobID() ID {
	return aph.BlobID
}

func (aph *AffectedPackageHandle) setBlob(rawBlobValue []byte) error {
	var blobValue AffectedPackageBlob
	if err := json.Unmarshal(rawBlobValue, &blobValue); err != nil {
		return fmt.Errorf("unable to unmarshal affected package blob value: %w", err)
	}

	aph.BlobValue = &blobValue
	return nil
}

// Package represents a package name within a known ecosystem, such as "python" or "golang".
type Package struct {
	ID ID `gorm:"column:id;primaryKey"`

	// Ecosystem is the tooling and language ecosystem that the package is released within
	Ecosystem string `gorm:"column:ecosystem;index:idx_package,unique,collate:NOCASE"`

	// Name is the name of the package within the ecosystem
	Name string `gorm:"column:name;index:idx_package,unique,collate:NOCASE;index:idx_package_name,collate:NOCASE"`

	// CPEs is the list of Common Platform Enumeration (CPE) identifiers that represent this package
	CPEs []Cpe `gorm:"foreignKey:PackageID;constraint:OnDelete:CASCADE;"`
}

func (p Package) String() string {
	var cpes []string
	for _, cpe := range p.CPEs {
		cpes = append(cpes, cpe.String())
	}
	if p.Ecosystem != "" && p.Name != "" {
		base := fmt.Sprintf("%s/%s", p.Ecosystem, p.Name)
		if len(cpes) == 0 {
			return base
		}

		return fmt.Sprintf("%s (%s)", base, strings.Join(cpes, ", "))
	}

	return strings.Join(cpes, ", ")
}

func (p Package) cacheKey() string {
	if p.Ecosystem == "" && p.Name == "" {
		return ""
	}
	// we're intentionally not including anything about CPEs here, since there is potentially a merge operation for
	// packages with CPEs we cannot reason about packages with CPEs in the cache, they must always pass through.
	return strings.ToLower(fmt.Sprintf("%s/%s", p.Ecosystem, p.Name))
}

func (p Package) rowID() ID {
	return p.ID
}

func (p *Package) tableName() string {
	return packagesTableCacheKey
}

func (p *Package) setRowID(i ID) {
	p.ID = i
}

func (p *Package) BeforeCreate(tx *gorm.DB) (err error) { // nolint:gocognit
	cacheInst, ok := cacheFromContext(tx.Statement.Context)
	if !ok {
		return fmt.Errorf("cache not found in context")
	}

	var existingPackage Package
	err = tx.Preload("CPEs").Where("ecosystem = ? collate nocase AND name = ? collate nocase", p.Ecosystem, p.Name).First(&existingPackage).Error
	if err == nil {
		// package exists; merge CPEs
		for _, newCPE := range p.CPEs {
			var existingCPE Cpe

			if existingID, ok := cacheInst.getID(&newCPE); ok {
				if err := tx.Where("id = ?", existingID).First(&existingCPE).Error; err != nil {
					if !errors.Is(err, gorm.ErrRecordNotFound) {
						return fmt.Errorf("failed to find CPE by ID %d: %w", existingID, err)
					}
				}
			}

			if existingCPE.ID != 0 {
				// if the record already exists, then we should use the existing record

				if existingCPE.PackageID == nil {
					log.WithFields("cpe", existingCPE, "pkg", existingPackage).Warn("CPE exists but was not associated with an already existing package until now")
					continue
				}

				if *existingCPE.PackageID != existingPackage.ID {
					return fmt.Errorf("CPE already exists for a different package (pkg=%v, existing_pkg=%v): %s", p.ID, existingPackage.ID, existingCPE)
				}
				continue
			}

			// if the CPE does not exist, proceed with creating it
			newCPE.PackageID = &existingPackage.ID
			existingPackage.CPEs = append(existingPackage.CPEs, newCPE)

			if err := tx.Create(&newCPE).Error; err != nil {
				return fmt.Errorf("failed to create CPE %v for package %v: %w", newCPE, existingPackage, err)
			}
		}
		// use the existing package instead of creating a new one
		*p = existingPackage
		return nil
	}

	// if the package does not exist, proceed with creating it
	for i := range p.CPEs {
		p.CPEs[i].PackageID = &p.ID
	}
	return nil
}

func (p *Package) AfterCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		cacheInst.set(p)
		for _, cpe := range p.CPEs {
			cacheInst.set(&cpe)
		}
	}
	return nil
}

// PackageSpecifierOverride is a table that allows for overriding fields on v6.PackageSpecifier instances when searching for specific Packages.
type PackageSpecifierOverride struct {
	Ecosystem string `gorm:"column:ecosystem;primaryKey;index:pkg_ecosystem_idx,collate:NOCASE"`

	// below are the fields that should be used as replacement for fields in the Packages table

	ReplacementEcosystem *string `gorm:"column:replacement_ecosystem;primaryKey"`
}

// OperatingSystem represents a specific release of an operating system. The resolution of the version is
// relative to the available data by the vulnerability data provider, so though there may be major.minor.patch OS
// releases, there may only be data available for major.minor.
type OperatingSystem struct {
	ID ID `gorm:"column:id;primaryKey"`

	// Name is the operating system family name (e.g. "debian")
	Name      string `gorm:"column:name;index:os_idx,unique;index,collate:NOCASE"`
	ReleaseID string `gorm:"column:release_id;index:os_idx,unique;index,collate:NOCASE"`

	// MajorVersion is the major version of a specific release (e.g. "10" for debian 10)
	MajorVersion string `gorm:"column:major_version;index:os_idx,unique;index"`

	// MinorVersion is the minor version of a specific release (e.g. "1" for debian 10.1)
	MinorVersion string `gorm:"column:minor_version;index:os_idx,unique;index"`

	// LabelVersion is an optional non-codename string representation of the version (e.g. "unstable" or for debian:sid)
	LabelVersion string `gorm:"column:label_version;index:os_idx,unique;index,collate:NOCASE"`

	// Codename is the codename of a specific release (e.g. "buster" for debian 10)
	Codename string `gorm:"column:codename;index,collate:NOCASE"`
}

func (o *OperatingSystem) VersionNumber() string {
	if o == nil {
		return ""
	}
	if o.MinorVersion != "" {
		return fmt.Sprintf("%s.%s", o.MajorVersion, o.MinorVersion)
	}
	return o.MajorVersion
}

func (o *OperatingSystem) Version() string {
	if o == nil {
		return ""
	}

	if o.LabelVersion != "" {
		return o.LabelVersion
	}

	if o.MajorVersion != "" {
		if o.MinorVersion != "" {
			return fmt.Sprintf("%s.%s", o.MajorVersion, o.MinorVersion)
		}
		return o.MajorVersion
	}

	return o.Codename
}

func (o OperatingSystem) String() string {
	return fmt.Sprintf("%s@%s", o.Name, o.Version())
}

func (o OperatingSystem) cacheKey() string {
	return strings.ToLower(o.String())
}

func (o OperatingSystem) rowID() ID {
	return o.ID
}

func (o *OperatingSystem) tableName() string {
	return operatingSystemsTableCacheKey
}

func (o *OperatingSystem) setRowID(i ID) {
	o.ID = i
}

func (o *OperatingSystem) clean() {
	o.MajorVersion = strings.TrimLeft(o.MajorVersion, "0")
	o.MinorVersion = strings.TrimLeft(o.MinorVersion, "0")
}

func (o *OperatingSystem) BeforeCreate(tx *gorm.DB) (err error) {
	o.clean()

	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		if existing, ok := cacheInst.getID(o); ok {
			o.setRowID(existing)
		}
		return nil
	}

	return fmt.Errorf("OS creation is not supported")
}

func (o *OperatingSystem) AfterCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		cacheInst.set(o)
	}
	return nil
}

// OperatingSystemSpecifierOverride is a table that allows for overriding fields on v6.OSSpecifier instances when searching for specific OperatingSystems.
type OperatingSystemSpecifierOverride struct {
	// Alias is an alternative name/ID for the operating system.
	Alias string `gorm:"column:alias;primaryKey;index:os_alias_idx,collate:NOCASE"`

	// Version is the matching version as found in the VERSION_ID field if the /etc/os-release file
	Version string `gorm:"column:version;primaryKey"`

	// VersionPattern is a regex pattern to match against the VERSION_ID field if the /etc/os-release file
	VersionPattern string `gorm:"column:version_pattern;primaryKey"`

	// Codename is the matching codename as found in the VERSION_CODENAME field if the /etc/os-release file
	Codename string `gorm:"column:codename"`

	// below are the fields that should be used as replacement for fields in the OperatingSystem table

	ReplacementName         *string `gorm:"column:replacement;primaryKey"`
	ReplacementMajorVersion *string `gorm:"column:replacement_major_version;primaryKey"`
	ReplacementMinorVersion *string `gorm:"column:replacement_minor_version;primaryKey"`
	ReplacementLabelVersion *string `gorm:"column:replacement_label_version;primaryKey"`
	Rolling                 bool    `gorm:"column:rolling;primaryKey"`
}

func (os *OperatingSystemSpecifierOverride) BeforeCreate(_ *gorm.DB) (err error) {
	if os.Version != "" && os.VersionPattern != "" {
		return fmt.Errorf("cannot have both version and version_pattern set")
	}

	return nil
}

// CPE related search tables //////////////////////////////////////////////////////

// AffectedCPEHandle represents a single CPE affected by the specified vulnerability. Note the CPEs in this table
// must NOT be resolvable to Packages (use AffectedPackageHandle for that). This table is used when the CPE is known,
// but we do not have a clear understanding of the package ecosystem or authoritative name, so we can still
// find vulnerabilities by these identifiers but not assert they are related to an entry in the Packages table.
type AffectedCPEHandle struct {
	ID              ID                   `gorm:"column:id;primaryKey"`
	VulnerabilityID ID                   `gorm:"column:vulnerability_id;not null"`
	Vulnerability   *VulnerabilityHandle `gorm:"foreignKey:VulnerabilityID"`

	CpeID ID   `gorm:"column:cpe_id;index"`
	CPE   *Cpe `gorm:"foreignKey:CpeID"`

	BlobID    ID                   `gorm:"column:blob_id"`
	BlobValue *AffectedPackageBlob `gorm:"-"`
}

func (ach AffectedCPEHandle) vulnerability() string {
	if ach.Vulnerability != nil {
		return ach.Vulnerability.Name
	}
	if ach.BlobValue != nil {
		if len(ach.BlobValue.CVEs) > 0 {
			return ach.BlobValue.CVEs[0]
		}
	}
	return ""
}

func (ach AffectedCPEHandle) String() string {
	var fields []string

	if ach.BlobValue != nil {
		v := ach.BlobValue.String()
		if v != "" {
			fields = append(fields, v)
		}
	}

	if ach.CPE != nil {
		fields = append(fields, fmt.Sprintf("cpe=%q", ach.CPE.String()))
	} else {
		fields = append(fields, fmt.Sprintf("cpe=%d", ach.CpeID))
	}

	if ach.Vulnerability != nil {
		fields = append(fields, fmt.Sprintf("vuln=%q", ach.Vulnerability.String()))
	} else {
		fields = append(fields, fmt.Sprintf("vuln=%d", ach.VulnerabilityID))
	}

	return fmt.Sprintf("affectedCPE(%s)", strings.Join(fields, ", "))
}

func (ach AffectedCPEHandle) getBlobID() ID {
	return ach.BlobID
}

func (ach AffectedCPEHandle) getBlobValue() any {
	if ach.BlobValue == nil {
		return nil // must return untyped nil or getBlobValue() == nil will always be false
	}
	return ach.BlobValue
}

func (ach *AffectedCPEHandle) setBlobID(id ID) {
	ach.BlobID = id
}

func (ach *AffectedCPEHandle) setBlob(rawBlobValue []byte) error {
	var blobValue AffectedPackageBlob
	if err := json.Unmarshal(rawBlobValue, &blobValue); err != nil {
		return fmt.Errorf("unable to unmarshal affected cpe blob value: %w", err)
	}

	ach.BlobValue = &blobValue
	return nil
}

type Cpe struct {
	// TODO: what about different CPE versions?
	ID        ID  `gorm:"primaryKey"`
	PackageID *ID `gorm:"column:package_id;index"`

	Part            string `gorm:"column:part;not null;index:idx_cpe,unique,collate:NOCASE"`
	Vendor          string `gorm:"column:vendor;index:idx_cpe,unique,collate:NOCASE;index:idx_cpe_vendor,collate:NOCASE"`
	Product         string `gorm:"column:product;not null;index:idx_cpe,unique,collate:NOCASE;index:idx_cpe_product,collate:NOCASE"`
	Edition         string `gorm:"column:edition;index:idx_cpe,unique,collate:NOCASE"`
	Language        string `gorm:"column:language;index:idx_cpe,unique,collate:NOCASE"`
	SoftwareEdition string `gorm:"column:software_edition;index:idx_cpe,unique,collate:NOCASE"`
	TargetHardware  string `gorm:"column:target_hardware;index:idx_cpe,unique,collate:NOCASE"`
	TargetSoftware  string `gorm:"column:target_software;index:idx_cpe,unique,collate:NOCASE"`
	Other           string `gorm:"column:other;index:idx_cpe,unique,collate:NOCASE"`
}

func (c Cpe) String() string {
	parts := []string{"cpe:2.3", c.Part, c.Vendor, c.Product, c.Edition, c.Language, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other}
	for i, part := range parts {
		if part == "" {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, ":")
}

func (c *Cpe) cacheKey() string {
	return strings.ToLower(c.String())
}

func (c *Cpe) tableName() string {
	return cpesTableCacheKey
}

func (c *Cpe) rowID() ID {
	return c.ID
}

func (c *Cpe) setRowID(i ID) {
	c.ID = i
}

func (c *Cpe) BeforeCreate(tx *gorm.DB) (err error) {
	cacheInst, ok := cacheFromContext(tx.Statement.Context)
	if !ok {
		return fmt.Errorf("CPE creation is not supported")
	}
	if existingID, ok := cacheInst.getID(c); ok {
		var existing Cpe
		result := tx.Where("id = ?", existingID).First(&existing)
		if result.Error == nil {
			if c.PackageID != nil && existing.PackageID != nil && *c.PackageID != *existing.PackageID {
				return fmt.Errorf("CPE already exists for a different package (pkg=%d, existing_pkg=%d): %q", *c.PackageID, *existing.PackageID, c)
			}

			// if the record already exists, then we should use the existing record
			*c = existing
		}

		c.setRowID(existingID)
	}
	return nil
}

func (c *Cpe) AfterCreate(tx *gorm.DB) (err error) {
	if cacheInst, ok := cacheFromContext(tx.Statement.Context); ok {
		cacheInst.set(c)
	}
	return nil
}

type KnownExploitedVulnerabilityHandle struct {
	ID int64 `gorm:"primaryKey"`

	Cve string `gorm:"column:cve;not null;index,collate:NOCASE"`

	BlobID    ID                               `gorm:"column:blob_id"`
	BlobValue *KnownExploitedVulnerabilityBlob `gorm:"-"`
}

func (v KnownExploitedVulnerabilityHandle) getBlobValue() any {
	if v.BlobValue == nil {
		return nil // must return untyped nil or getBlobValue() == nil will always be false
	}
	return v.BlobValue
}

func (v *KnownExploitedVulnerabilityHandle) setBlobID(id ID) {
	v.BlobID = id
}

func (v KnownExploitedVulnerabilityHandle) getBlobID() ID {
	return v.BlobID
}

func (v *KnownExploitedVulnerabilityHandle) setBlob(rawBlobValue []byte) error {
	var blobValue KnownExploitedVulnerabilityBlob
	if err := json.Unmarshal(rawBlobValue, &blobValue); err != nil {
		return fmt.Errorf("unable to unmarshal KEV blob value: %w", err)
	}

	v.BlobValue = &blobValue
	return nil
}

type EpssMetadata struct {
	Date time.Time `gorm:"column:date;not null"`
}

type EpssHandle struct {
	ID int64 `gorm:"primaryKey"`

	Cve        string    `gorm:"column:cve;not null;index,collate:NOCASE"`
	Epss       float64   `gorm:"column:epss;not null"`
	Percentile float64   `gorm:"column:percentile;not null"`
	Date       time.Time `gorm:"-"` // note we do not store the date in this table since it is expected to be the same for all records, that is what EpssMetadata is for
}
