package v6

import (
	"fmt"
	"gorm.io/gorm"
	"time"
)

func All() []any {
	return []any{
		&Cpe{},
		&PlatformCpe{},
		&Digest{},
		&Alias{},
		&Blob{},
		&DbMetadata{},
		//&DbSpecificNvd{},
		&Epss{},
		&KnownExploitedVulnerability{},
		&OperatingSystem{},
		&Provider{},
		&Reference{},
		&Severity{},
		&Affected{},
		&Vulnerability{},
	}
}

// core vulnerability types

// TODO: this will probably be shipped as another DB and attached on as-needed basis
type Blob struct {
	Digest string `gorm:"column:digest;primaryKey"`
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

// Vulnerability represents the core advisory record for a single known vulnerability from a specific provider. There
// may be multiple vulnerabilities with the same name.
type Vulnerability struct {
	ID int64 `gorm:"column:id;primaryKey"`

	// ProviderID is the foreign key to the Provider table which indicates the upstream data source for this vulnerability.
	ProviderID string `gorm:"column:provider_id;not null;index:idx_vulnerability_provider"`

	//// ProviderNamespace is an optional field reserved for logical grouping of vulnerabilities from the same provider (e.g. OS version number)
	//ProviderNamespace string `gorm:"column:provider_namespace;not null;index:idx_vulnerability_provider"`

	// Provider is the result of a join with the Provider table, which represents all information about where this vulnerability record came from.
	Provider *Provider

	// Name of the vulnerability (e.g. CVE-2024-34102 or GHSA-85rg-8m6h-825p). This is the same as the OSV ID field.
	Name string `gorm:"column:name;not null;index;index:idx_vulnerability_provider"`

	// Modified is the time the entry was last modified, as an RFC3339-formatted timestamp in UTC (ending in “Z”) (mirrors the OSV field)
	Modified string `gorm:"column:modified"`

	// Published is the time the entry should be considered to have been published, as an RFC3339-formatted time stamp in UTC (ending in “Z”) (mirrors the OSV field)
	Published string `gorm:"column:published"`

	// Withdrawn is the time the entry should be considered to have been withdrawn, as an RFC3339-formatted timestamp in UTC (ending in “Z”) (mirrors the OSV field)
	Withdrawn string `gorm:"column:withdrawn"`

	Status string `gorm:"column:status"` // example: "active, withdrawn, rejected, ..." could be an enum

	//Summary string `gorm:"column:summary"`
	//Detail string `gorm:"column:detail;index,unique"`
	DetailDigest string `gorm:"column:detail_digest;index,unique"`
	//Detail       *Blob  `gorm:"foreignKey:DetailDigest"`

	// References are URLs to external resources that provide more information about the vulnerability (mirrors the OSV field)
	References *[]Reference `gorm:"foreignKey:VulnerabilityID"`

	// Related is s a list of IDs of closely related vulnerabilities but are not aliases for the vulnerability (mirrors the OSV field)
	//Related *[]Related `gorm:"many2many:vulnerability_related"`

	// Aliases is a list of IDs of the same vulnerability in other databases, in the form of the Name field. This allows one database to claim that its own entry describes the same vulnerability as one or more entries in other databases. (mirrors the OSV field)
	Aliases *[]Alias `gorm:"many2many:vulnerability_aliases"`

	// Severities is a list of severity indications (quantitative or qualitative) for the vulnerability (mirrors the OSV field, but the semantics are different. We allow for qualitative string severity, where OSV does not)
	Severities *[]Severity `gorm:"many2many:vulnerability_severities"`

	// DB specific info
	//DbSpecific *datatypes.JSON `gorm:"many2many:vulnerability_db_specific"`

	// Affected is a list of affected entries related to this vulnerability
	Affected *[]Affected `gorm:"foreignKey:VulnerabilityID"`

	batchWriteAffected *[]Affected `gorm:"-"`
}

func (a *Vulnerability) BeforeSave(tx *gorm.DB) (err error) {
	if a.Severities != nil {
		uniqueSevs, err := a.uniqueSevs(tx)
		if err != nil {
			return err
		}
		a.Severities = uniqueSevs
	}

	return nil
}

func (a *Vulnerability) uniqueSevs(tx *gorm.DB) (*[]Severity, error) {
	var uniqueSevs []Severity
	for _, sev := range *a.Severities {
		var existing Severity
		result := tx.Where("type = ? AND score = ? AND source = ? AND rank = ?", sev.Type, sev.Score, sev.Source, sev.Rank).First(&existing)
		if result.Error == nil {
			uniqueSevs = append(uniqueSevs, existing)
		} else {
			err := tx.Create(&sev).Error
			if err != nil {
				return nil, err
			}
			uniqueSevs = append(uniqueSevs, sev)
		}
	}
	return &uniqueSevs, nil
}

func (c *Vulnerability) BeforeCreate(tx *gorm.DB) error {
	// if the len of Affected is > 500, then create those in batches and then attach those to the Vulnerability
	if c.Affected != nil && len(*c.Affected) > 500 {
		c.batchWriteAffected = c.Affected
		c.Affected = nil
	}

	return nil
}

func (c *Vulnerability) AfterCreate(tx *gorm.DB) error {
	if c.batchWriteAffected == nil {
		return nil
	}

	// create in batches...

	var affecteds []*Affected
	affs := *c.batchWriteAffected
	for i := range affs {
		a := affs[i]
		a.VulnerabilityID = c.ID
		affecteds = append(affecteds, &a)
	}

	if err := tx.CreateInBatches(affecteds, 500).Error; err != nil {
		return fmt.Errorf("failed to create affecteds in batches: %w", err)
	}
	affs = make([]Affected, len(affecteds))
	for i := range affecteds {
		affs[i] = *affecteds[i]
	}
	c.Affected = &affs
	c.batchWriteAffected = nil

	return nil
}

// TODO: can I do this?
//type DBSpecific[T any] struct {
//	Kind string `json:"kind"`
//	Data T      `json:"data"`
//}

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

// Alias represents a single alias for a vulnerability
type Alias struct {
	ID int64 `gorm:"column:id;primaryKey"`
	//VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	Alias string `gorm:"column:alias;not null,index:idx_alias,unique"`
}

//type CVSS struct {
//	Vector string `gorm:"column:vector"`
//
//	// Source is the name of the source of the severity score (e.g. "nvd@nist.gov" or "security-advisories@github.com")
//	Source string `gorm:"column:source"`
//
//	Vendor datatypes.JSON `gorm:"column:vendor"`
//
//	// Rank is a free-form organizational field to convey priority over other severities
//	Rank int `gorm:"column:priority"`
//}

// Severity represents a single severity record for a vulnerability
type Severity struct {
	ID int64 `gorm:"column:id;primaryKey"`

	// Type describes the quantitative method used to determine the Score, such as "CVSS_V3". Alternatively this makes claim that Score is qualitative, such as just simply "string"
	Type string `gorm:"column:type;index:idx_severity,unique"`

	// Score is the quantitative or qualitative severity score (e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" or "high")
	Score string `gorm:"column:score;not null;index:idx_severity,unique"`

	// Source is the name of the source of the severity score (e.g. "nvd@nist.gov" or "security-advisories@github.com")
	Source string `gorm:"column:source;index:idx_severity,unique"`

	// Rank is a free-form organizational field to convey priority over other severities
	Rank int `gorm:"column:rank;index:idx_severity,unique"`
}

//func (c *Severity) BeforeCreate(tx *gorm.DB) (err error) {
//	// if the name, major version, and minor version already exist in the table then we should not insert a new record
//	var existing Severity
//	result := tx.Where("type = ? AND score = ? AND source = ? AND rank = ?", c.Type, c.Score, c.Source, c.Rank).First(&existing)
//	if result.Error == nil {
//		// if the record already exists, then we should use the existing record
//		*c = existing
//	}
//	return nil
//}

type Reference struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	Type string `gorm:"column:type;not null"`
	URL  string `gorm:"column:url;not null"`
}

// DB specific info

type DbSpecificNvd struct {
	VulnStatus            string
	CisaExploitAdd        string
	CisaActionDue         string
	CisaRequiredAction    string
	CisaVulnerabilityName string
}

// affected package info

// Affected represents a single package or set of digests that are affected by a vulnerability
type Affected struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id,not null"`

	OperatingSystemID *int64           `gorm:"column:operating_system_id"`
	OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`

	VersionConstraint string `gorm:"column:version_constraint"`
	VersionFormat     string `gorm:"column:version_format"`

	// package qualifiers

	PlatformCpes *[]PlatformCpe `gorm:"many2many:affected_platform_cpes"`

	RpmModularity string `gorm:"column:rpm_modularity"`

	// identifiers

	Package *Package `gorm:"embedded;embeddedPrefix:package_"`
	//Digests *[]Digest `gorm:"many2many:affected_digests"`
	Cpes *[]Cpe `gorm:"many2many:affected_cpes"`

	// fix

	Fix *Fix `gorm:"embedded;embeddedPrefix:fix_"`
}

func (a *Affected) BeforeSave(tx *gorm.DB) (err error) {
	if a.Cpes != nil {
		uniqueCpes, err := a.uniqueCpes(tx)
		if err != nil {
			return err
		}
		a.Cpes = uniqueCpes
	}

	if a.PlatformCpes != nil {
		uniqueCpes, err := a.uniquePlatformCpes(tx)
		if err != nil {
			return err
		}
		a.PlatformCpes = uniqueCpes
	}

	if a.OperatingSystem != nil {
		result := tx.Where("name = ? AND major_version = ? AND minor_version = ?", a.OperatingSystem.Name, a.OperatingSystem.MajorVersion, a.OperatingSystem.MinorVersion).First(&a.OperatingSystem)
		if result.Error != nil {
			err := tx.Create(&a.OperatingSystem).Error
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func (a *Affected) uniquePlatformCpes(tx *gorm.DB) (*[]PlatformCpe, error) {
	var uniqueCpes []PlatformCpe
	for _, cpe := range *a.PlatformCpes {
		var existing PlatformCpe
		result := tx.Where("type = ? AND vendor = ? AND product = ? AND edition = ? AND language = ? AND version = ? AND version_update = ? AND software_edition = ? AND target_hardware = ? AND target_software = ? AND other = ?",
			cpe.Type, cpe.Vendor, cpe.Product, cpe.Edition, cpe.Language, cpe.Version, cpe.VersionUpdate, cpe.SoftwareEdition, cpe.TargetHardware, cpe.TargetSoftware, cpe.Other).First(&existing)
		if result.Error == nil {
			uniqueCpes = append(uniqueCpes, existing)
		} else {
			err := tx.Create(&cpe).Error
			if err != nil {
				return nil, err
			}
			uniqueCpes = append(uniqueCpes, cpe)
		}
	}
	return &uniqueCpes, nil
}

func (a *Affected) uniqueCpes(tx *gorm.DB) (*[]Cpe, error) {
	var uniqueCpes []Cpe
	for _, cpe := range *a.Cpes {
		var existing Cpe
		result := tx.Where("type = ? AND vendor = ? AND product = ? AND edition = ? AND language = ? AND software_edition = ? AND target_hardware = ? AND target_software = ? AND other = ?",
			cpe.Type, cpe.Vendor, cpe.Product, cpe.Edition, cpe.Language, cpe.SoftwareEdition, cpe.TargetHardware, cpe.TargetSoftware, cpe.Other).First(&existing)
		if result.Error == nil {
			uniqueCpes = append(uniqueCpes, existing)
		} else {
			err := tx.Create(&cpe).Error
			if err != nil {
				return nil, err
			}
			uniqueCpes = append(uniqueCpes, cpe)
		}
	}
	return &uniqueCpes, nil
}

// TODO: add later and reuse existing similar tables with many2many
//type NotAffected struct {
//	ID              int64 `gorm:"column:id;primaryKey"`
//	VulnerabilityID int64 `gorm:"column:vulnerability_id,not null"`
//
//	PackageID *int64 `gorm:"column:package_id"`
//	Package   *Package
//
//	Versions        *[]AffectedVersion        `gorm:"foreignKey:AffectedID"`
//	ExcludeVersions *[]AffectedExcludeVersion `gorm:"foreignKey:AffectedID"`
//	Range           *[]Range                  `gorm:"foreignKey:AffectedID"`
//
//	// Digests that are known to correspond to this vulnerability, but cannot be closely associated with a package
//	Digests *[]Digests `gorm:"many2many:not_affected_digests"`
//}

type Fix struct {
	Version string `gorm:"column:version"`
	State   string `gorm:"column:state"`
	//Detail  *FixDetail
}

//type FixDetail struct {
//	ID int64 `gorm:"primaryKey"`
//
//	GitCommit      *string `gorm:"column:git_commit"`
//	PullRequestURL *string `gorm:"column:pull_request_url"`
//	Timestamp      *string `gorm:"column:timestamp"`
//	// TODO: what else here?
//}

// primary package identifiers (search entrypoints)

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

//func (c *Cpe) BeforeCreate(tx *gorm.DB) (err error) {
//	// if the name, major version, and minor version already exist in the table then we should not insert a new record
//	var existing Cpe
//	result := tx.Where("type = ? AND vendor = ? AND product = ? AND edition = ? AND language = ? AND software_edition = ? AND target_hardware = ? AND target_software = ? AND other = ?", c.Type, c.Vendor, c.Product, c.Edition, c.Language, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other).First(&existing)
//	if result.Error == nil {
//		// if the record already exists, then we should use the existing record
//		*c = existing
//	}
//	return nil
//}

type PlatformCpe struct {
	// TODO: what about different CPE versions?
	ID int64 `gorm:"primaryKey"`

	Type            string `gorm:"column:type;not null;index:idx_platform_cpe,unique"`
	Vendor          string `gorm:"column:vendor;index:idx_platform_cpe,unique"`
	Product         string `gorm:"column:product;not null;index:idx_platform_cpe,unique"`
	Edition         string `gorm:"column:edition;index:idx_platform_cpe,unique"`
	Language        string `gorm:"column:language;index:idx_platform_cpe,unique"`
	Version         string `gorm:"column:version;index:idx_platform_cpe,unique"`
	VersionUpdate   string `gorm:"column:version_update;index:idx_platform_cpe,unique"`
	SoftwareEdition string `gorm:"column:software_edition;index:idx_platform_cpe,unique"`
	TargetHardware  string `gorm:"column:target_hardware;index:idx_platform_cpe,unique"`
	TargetSoftware  string `gorm:"column:target_software;index:idx_platform_cpe,unique"`
	Other           string `gorm:"column:other;index:idx_platform_cpe,unique"`
}

func (c PlatformCpe) String() string {
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s", c.Type, c.Vendor, c.Product, c.Edition, c.Language, c.Version, c.VersionUpdate, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other)
}

//func (c *PlatformCpe) BeforeCreate(tx *gorm.DB) (err error) {
//	// if the name, major version, and minor version already exist in the table then we should not insert a new record
//	var existing PlatformCpe
//	result := tx.Where("type = ? AND vendor = ? AND product = ? AND edition = ? AND language = ? AND version = ? AND version_update = ? AND software_edition = ? AND target_hardware = ? AND target_software = ? AND other = ?", c.Type, c.Vendor, c.Product, c.Edition, c.Language, c.Version, c.VersionUpdate, c.SoftwareEdition, c.TargetHardware, c.TargetSoftware, c.Other).First(&existing)
//	if result.Error == nil {
//		// if the record already exists, then we should use the existing record
//		*c = existing
//	}
//	return nil
//}

// Digest represents arbitrary digests that can be associated with a vulnerability such that if found the material can be considered to be affected by this vulnerability
type Digest struct {
	Algorithm string `gorm:"column:algorithm"`
	Value     string `gorm:"column:value"`
}

type Package struct {
	// TODO: setup unique indexes only for writing and drop before shipping for the best size tradeoff

	// TODO: break purl out into fields here
	Type string `gorm:"column:type;index:idx_package"` // TODO: NVD doesn't have this, should this be nullable?
	Name string `gorm:"column:name;index:idx_package"`

	//OperatingSystemID *int64           `gorm:"column:operating_system_id"`
	//OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`
	//
	//Purls *[]Purl `gorm:"many2many:package_purls"`
	//Cpes  *[]Cpes  `gorm:"many2many:package_cpes"`

}

//func (c *Package) BeforeCreate(tx *gorm.DB) (err error) {
//	// if the name, major version, and minor version already exist in the table then we should not insert a new record
//	var existing Package
//	result := tx.Where("name = ? AND ecosystem = ?", c.Name, c.Ecosystem).First(&existing)
//	if result.Error == nil {
//		// if the record already exists, then we should use the existing record
//		*c = existing
//	}
//	return nil
//}

//type Purl struct {
//	ID int64 `gorm:"column:id;primaryKey"`
//
//	//Schema    *string `gorm:"column:schema"`
//	Type      string  `gorm:"column:type"`
//	//Namespace *string `gorm:"column:namespace"`
//	Name      string  `gorm:"column:name"`
//	//Version   *string `gorm:"column:version"`
//	//SubPath   *string `gorm:"column:subpath"`
//	//
//	//Qualifiers *[]Qualifier `gorm:"many2many:purl_qualifiers"`
//}

// secondary package identifier information
//
//type Qualifier struct {
//	ID int64 `gorm:"column:id;primaryKey"`
//
//	Key   string `gorm:"column:key"`
//	Value string `gorm:"column:value"`
//}

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

type DbMetadata struct {
	BuildTimestamp *time.Time `gorm:"column:build_timestamp;not null"`
	Model          int        `gorm:"column:model;not null"`
	Revision       int        `gorm:"column:revision;not null"`
	Addition       int        `gorm:"column:addition;not null"`
}

// TODO: not clear that we need this...
//type Comment struct {
//	ID int64 `gorm:"column:id;primaryKey"`
//
//	Value string `gorm:"column:value"`
//}

// TODO: should this be an attached data source? (like with blobs?)
/*
   {
         "cveID": "CVE-2022-22536",
         "vendorProject": "SAP",
         "product": "Multiple Products",
         "vulnerabilityName": "SAP Multiple Products HTTP Request Smuggling Vulnerability",
         "dateAdded": "2022-08-18",
         "shortDescription": "SAP NetWeaver Application Server ABAP, SAP NetWeaver Application Server Java, ABAP Platform, SAP Content Server and SAP Web Dispatcher allow HTTP request smuggling. An unauthenticated attacker can prepend a victim's request with arbitrary data, allowing for function execution impersonating the victim or poisoning intermediary Web caches.",
         "requiredAction": "Apply updates per vendor instructions.",
         "dueDate": "2022-09-08",
         "knownRansomwareCampaignUse": "Unknown",
         "notes": "SAP users must have an account in order to login and access the patch. https:\/\/accounts.sap.com\/saml2\/idp\/sso"
     },
*/
type KnownExploitedVulnerability struct {
	ID int64 `gorm:"primaryKey"`

	CatalogID                  int64  `gorm:"column:catalog_id;not null"`
	Cve                        string `gorm:"column:cve;not null"`
	VendorProject              string `gorm:"column:vendor_project;not null"`
	Product                    string `gorm:"column:product;not null"`
	VulnerabilityName          string `gorm:"column:vulnerability_name;not null"`
	DateAdded                  string `gorm:"column:date_added;not null"`        // TODO: time.time?
	ShortDescription           string `gorm:"column:short_description;not null"` // TODO: blob digest?
	RequiredAction             string `gorm:"column:required_action;not null"`
	DueDate                    string `gorm:"column:due_date;not null"`
	KnownRansomwareCampaignUse string `gorm:"column:known_ransomware_campaign_use"`
	Notes                      string `gorm:"column:notes"` // TODO: blob digest?
}

// TODO: should this be an attached data source? (like with blobs?)
/*
	{
		"cve":"CVE-2024-6046",
		"epss":"0.000900000",
		"percentile":"0.385690000",
		"date":"2024-06-18",
	}
*/
type Epss struct {
	ID int64 `gorm:"primaryKey"`

	Cve        string `gorm:"column:cve;not null"`
	Epss       string `gorm:"column:epss;not null"`       // TODO: should we normalize this to not a string?
	Percentile string `gorm:"column:percentile;not null"` // TODO: should we normalize this to not a string?
	Date       string `gorm:"column:date;not null"`       // TODO: time.time?
}
