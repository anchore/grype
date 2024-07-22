package v6

import (
	"fmt"
	"gorm.io/gorm"
	"time"
)

func All() []any {
	return []any{
		// non-domain info
		&DbMetadata{},

		// data source info
		&Provider{},

		// core data store
		&Blob{},

		// package related search tables
		&AffectedPackageHandle{},    // join on package, operating system
		&NotAffectedPackageHandle{}, // join on package, operating system
		&OperatingSystem{},
		&Package{},

		// CPE related search tables
		&AffectedCPEHandle{},    // join on CPE
		&NotAffectedCPEHandle{}, // join on CPE
		&Cpe{},

		// vulnerability related search tables
		&VulnerabilityHandle{},
		&KnownExploitedVulnerabilityHandle{},
		&EpssHandle{},
	}
}

// Non-domain info //////////////////////////////////////////////////////

type DbMetadata struct {
	BuildTimestamp *time.Time `gorm:"column:build_timestamp;not null"`
	Model          int        `gorm:"column:model;not null"`
	Revision       int        `gorm:"column:revision;not null"`
	Addition       int        `gorm:"column:addition;not null"`
}

// data source info //////////////////////////////////////////////////////

// Provider is the upstream data processor (usually Vunnel) that is responsible for vulnerability records. Each provider
// should be scoped to a specific vulnerability dataset, for instance, a "ubuntu" provider for all records from
// Canonicals' Ubuntu Security Notices (for all Ubuntu distro versions).
type Provider struct {
	// Name of the Vunnel provider (or sub processor responsible for data records from a single specific source, e.g. "ubuntu")
	ID string `gorm:"column:name;primaryKey"`

	// Version of the Vunnel provider (or sub processor equivalent)
	Version string `gorm:"column:version"`

	// Processor is the name of the application that processed the data (e.g. "vunnel")
	Processor string `gorm:"column:processor"`

	// DateCaptured is the timestamp which the upstream data was pulled and processed
	DateCaptured *time.Time `gorm:"column:date_captured"`

	// InputDigest is a self describing hash (e.g. sha256:123... not 123...) of all data used by the provider to generate the vulnerability records
	InputDigest string `gorm:"column:input_digest"`

	// InstanceCacheURL is the URL to where a cache of the post-processed provider data can be found (ideally this should be content addressable)
	InstanceCacheURL string `gorm:"column:instance_cache_url"` // TODO: how to get this from the static data store? probably written by oras step...

	// SourceURL is the URL to the upstream data source (e.g. the URL to the Ubuntu Security Notices page)
	SourceURL string `gorm:"column:source_url"` // TODO: multiple...
}

// core data store //////////////////////////////////////////////////////

type Blob struct {
	ID     int64  `gorm:"column:id;primaryKey"`
	Digest string `gorm:"column:digest;not null;unique"` // TODO: drop this after finalizing the DB
	Value  string `gorm:"column:value;not null"`
}

func (b *Blob) BeforeCreate(tx *gorm.DB) (err error) {
	// if the name, major version, and minor version already exist in the table then we should not insert a new record
	var existing Blob
	result := tx.Where("digest = ?", b.Digest).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*b = existing
	}
	return nil
}

// package related search tables //////////////////////////////////////////////////////

// AffectedPackageHandle represents a single package affected by the specified vulnerability.
type AffectedPackageHandle struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	OperatingSystemID *int64           `gorm:"column:operating_system_id"`
	OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`

	PackageID int64    `gorm:"column:package_id"`
	Package   *Package `gorm:"foreignKey:PackageID"`

	BlobID    int64         `gorm:"column:blob_id"`
	Blob      *Blob         `gorm:"foreignKey:BlobID"`
	BlobValue *AffectedBlob `gorm:"-"`
}

// NotAffectedPackageHandle represents a single package that is positively not affected by the specified vulnerability.
type NotAffectedPackageHandle struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	OperatingSystemID *int64           `gorm:"column:operating_system_id"`
	OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`

	PackageID int64    `gorm:"column:package_id"`
	Package   *Package `gorm:"column:package;foreignKey:PackageID"`

	BlobID    int64            `gorm:"column:blob_id"`
	Blob      *Blob            `gorm:"foreignKey:BlobID"`
	BlobValue *NotAffectedBlob `gorm:"-"`
}

type Package struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Type string `gorm:"column:type;index:idx_package,unique"`
	Name string `gorm:"column:name;index:idx_package,unique"`
}

func (p *Package) BeforeCreate(tx *gorm.DB) (err error) {
	// if the name and version exists, then use the existing Package
	var existing Package
	result := tx.Where("type = ? AND name = ?", p.Type, p.Name).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*p = existing
	}
	return nil
}

type OperatingSystem struct {
	ID int64 `gorm:"column:id;primaryKey"`

	Name         string `gorm:"column:name;index:os_idx,unique"`
	MajorVersion string `gorm:"column:major_version;index:os_idx,unique"`
	MinorVersion string `gorm:"column:minor_version;index:os_idx,unique"`
	Codename     string `gorm:"column:codename"`
}

func (os *OperatingSystem) BeforeCreate(tx *gorm.DB) (err error) {
	// if the name, major version, and minor version already exist in the table then we should not insert a new record
	var existing OperatingSystem
	result := tx.Where("name = ? AND major_version = ? AND minor_version = ?", os.Name, os.MajorVersion, os.MinorVersion).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*os = existing
	}
	return nil
}

// CPE related search tables //////////////////////////////////////////////////////

// AffectedCPEHandle represents a single CPE affected by the specified vulnerability
type AffectedCPEHandle struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	CpeID int64 `gorm:"column:cpe_id"`
	CPE   *Cpe  `gorm:"foreignKey:CpeID"`

	BlobID    int64         `gorm:"column:blob_id"`
	Blob      *Blob         `gorm:"foreignKey:BlobID"`
	BlobValue *AffectedBlob `gorm:"-"`
}

// NotAffectedCPEHandle represents a single CPE affected by the specified vulnerability
type NotAffectedCPEHandle struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	CpeID int64 `gorm:"column:cpe_id"`
	CPE   *Cpe  `gorm:"foreignKey:CpeID"`

	BlobID    int64            `gorm:"column:blob_id"`
	Blob      *Blob            `gorm:"foreignKey:BlobID"`
	BlobValue *NotAffectedBlob `gorm:"-"`
}

type Cpe struct {
	// TODO: what about different CPE versions?
	ID int64 `gorm:"primaryKey"`

	Type            string `gorm:"column:type;not null;index:idx_cpe,unique"`
	Vendor          string `gorm:"column:vendor;index:idx_cpe,unique"`
	Product         string `gorm:"column:product;not null;index:idx_cpe,unique"`
	Edition         string `gorm:"column:edition;index:idx_cpe,unique"`
	Language        string `gorm:"column:language;index:idx_cpe,unique"`
	SoftwareEdition string `gorm:"column:software_edition;index:idx_cpe,unique"`
	TargetHardware  string `gorm:"column:target_hardware;index:idx_cpe,unique"`
	TargetSoftware  string `gorm:"column:target_software;index:idx_cpe,unique"`
	Other           string `gorm:"column:other;index:idx_cpe,unique"`
}

func (c Cpe) String() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s:%s", c.Type, c.Vendor, c.Product, c.Edition, c.Language, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other)
}

func (c *Cpe) BeforeCreate(tx *gorm.DB) (err error) {
	// if the name, major version, and minor version already exist in the table then we should not insert a new record
	var existing Cpe
	result := tx.Where("type = ? AND vendor = ? AND product = ? AND edition = ? AND language = ? AND software_edition = ? AND target_hardware = ? AND target_software = ? AND other = ?", c.Type, c.Vendor, c.Product, c.Edition, c.Language, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*c = existing
	}
	return nil
}

// Vulnerability related search tables //////////////////////////////////////////////////////

// VulnerabilityHandle represents the pointer to the core advisory record for a single known vulnerability from a specific provider.
type VulnerabilityHandle struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name;not null;index"`

	BlobID    int64              `gorm:"column:blob_id"`
	Blob      *Blob              `gorm:"foreignKey:BlobID"`
	BlobValue *VulnerabilityBlob `gorm:"-"`
}

// KnownExploitedVulnerabilityHandle represents the pointer to the core advisory record for a single known exploited vulnerability CISA dataset.
type KnownExploitedVulnerabilityHandle struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name;not null;index"`

	BlobID    int64                            `gorm:"column:blob_id"`
	Blob      *Blob                            `gorm:"foreignKey:BlobID"`
	BlobValue *KnownExploitedVulnerabilityBlob `gorm:"-"`
}

// EpssHandle represents the pointer to the vulnerability severity record from the EPSS dataset.
type EpssHandle struct {
	ID   int64  `gorm:"column:id;primaryKey"`
	Name string `gorm:"column:name;not null;index"`

	BlobID    int64     `gorm:"column:blob_id"`
	Blob      *Blob     `gorm:"foreignKey:BlobID"`
	BlobValue *EpssBlob `gorm:"-"`
}
