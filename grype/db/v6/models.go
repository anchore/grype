package v6

import (
	"gorm.io/gorm"
	"time"
)

func All() []any {
	return []any{
		&Cpe{},
		&Digest{},
		&AffectedSeverity{},
		&AffectedVersion{},
		&Affected{},
		&Alias{},
		&Blob{},
		//&Comment{},
		&DbMetadata{},
		&DbSpecificNvd{},
		&Epss{},
		&KnownExploitedVulnerability{},
		&LogicalPackage{},
		&AffectedExcludeVersion{},
		&OperatingSystem{},
		&PackageQualifierPlatformCpe{},
		&PackageQualifierRpmModularity{},
		&Package{},
		&Provider{},
		&RangeEvent{},
		//&RangeEventMetadata{},
		&Range{},
		&Reference{},
		&Related{},
		&Severity{},
		&Vulnerability{},
	}
}

// core vulnerability types

// Vulnerability represents the core advisory record for a single known vulnerability from a specific provider. There
// may be multiple vulnerabilities with the same name.
type Vulnerability struct {
	ID int64 `gorm:"column:id;primaryKey"`

	// ProviderID is the foreign key to the Provider table which indicates the upstream data source for this vulnerability.
	ProviderID string `gorm:"column:provider_id;not null;index:idx_vulnerability_provider"`

	// Provider is the result of a join with the Provider table, which represents all information about where this vulnerability record came from.
	Provider *Provider

	// Name of the vulnerability (e.g. CVE-2024-34102 or GHSA-85rg-8m6h-825p). This is the same as the OSV ID field.
	Name string `gorm:"column:name;not null;index;index:idx_vulnerability_provider"`

	// Modified is the time the entry was last modified, as an RFC3339-formatted timestamp in UTC (ending in “Z”) (mirrors the OSV field)
	Modified *string `gorm:"column:modified"`

	// Published is the time the entry should be considered to have been published, as an RFC3339-formatted time stamp in UTC (ending in “Z”) (mirrors the OSV field)
	Published *string `gorm:"column:published"`

	// Withdrawn is the time the entry should be considered to have been withdrawn, as an RFC3339-formatted timestamp in UTC (ending in “Z”) (mirrors the OSV field)
	Withdrawn *string `gorm:"column:withdrawn"`

	// SummaryDigest is a self describing hash (e.g. sha256:123... not 123...) of the summary field from the OSV summary field. This digest is searched against the Blob table/DB.
	SummaryDigest *string `gorm:"column:summary_digest"`

	// DetailDigest is a self describing hash (e.g. sha256:123... not 123...) of the detail field from the OSV summary field. This digest is searched against the Blob table/DB.
	DetailDigest *string `gorm:"column:detail_digest"`

	// References are URLs to external resources that provide more information about the vulnerability (mirrors the OSV field)
	References *[]Reference `gorm:"foreignKey:VulnerabilityID"`

	// Related is s a list of IDs of closely related vulnerabilities but are not aliases for the vulnerability (mirrors the OSV field)
	Related *[]Related `gorm:"many2many:vulnerability_related"`

	// Aliases is a list of IDs of the same vulnerability in other databases, in the form of the Name field. This allows one database to claim that its own entry describes the same vulnerability as one or more entries in other databases. (mirrors the OSV field)
	Aliases *[]Alias `gorm:"many2many:vulnerability_aliases"`

	// Severities is a list of severity indications (quantitative or qualitative) for the vulnerability (mirrors the OSV field, but the semantics are different. We allow for qualitative string severity, where OSV does not)
	Severities *[]Severity `gorm:"many2many:vulnerability_severities"`

	// DB specific info
	DbSpecificNvd *[]DbSpecificNvd `gorm:"foreignKey:VulnerabilityID"`

	// Affected is a list of affected entries related to this vulnerability
	Affected *[]Affected `gorm:"foreignKey:VulnerabilityID"`
}

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

// Related represents a single related vulnerability name
type Related struct {
	ID int64 `gorm:"column:id;primaryKey"`
	//VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	// Name of the related vulnerability (e.g. CVE-2024-34102 or GHSA-85rg-8m6h-825p)
	Name string `gorm:"column:name;not null,index:idx_related,unique"`

	//// Reason is a free-form text field that describes the relationship between the two vulnerabilities ("CVE-2022-12345 might be related to CVE-2022-54321 because both affect the same software library but are distinct issues")
	//Reason string `gorm:"column:reason"`
}

// Severity represents a single severity record for a vulnerability
type Severity struct {
	ID int64 `gorm:"column:id;primaryKey"`

	// Type describes the quantitative method used to determine the Score, such as "CVSS_V3". Alternatively this makes claim that Score is qualitative, such as just simply "string"
	Type string `gorm:"column:type;not null"`

	// Score is the quantitative or qualitative severity score (e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N" or "high")
	Score string `gorm:"column:score;not null"`

	// Source is the name of the source of the severity score (e.g. "nvd@nist.gov" or "security-advisories@github.com")
	Source *string `gorm:"column:source"`

	// Priority is a free-form organizational field to convey priority over other severities (e.g. primary vs secondary or authoritative vs unverified)
	Priority *string `gorm:"column:priority"` // TODO: naming is hard...
}

type Reference struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	Type string `gorm:"column:type;not null"`
	URL  string `gorm:"column:url;not null"`
}

// DB specific info

type DbSpecificNvd struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id;not null"`

	VulnStatus            string `gorm:"column:vulnStatus"`
	CisaExploitAdd        string `gorm:"column:cisaExploitAdd"`
	CisaActionDue         string `gorm:"column:cisaActionDue"`
	CisaRequiredAction    string `gorm:"column:cisaRequiredAction"`
	CisaVulnerabilityName string `gorm:"column:cisaVulnerabilityName"`
}

// affected package info

// Affected represents a single package or set of digests that are affected by a vulnerability
type Affected struct {
	ID              int64 `gorm:"column:id;primaryKey"`
	VulnerabilityID int64 `gorm:"column:vulnerability_id,not null"`

	PackageID *int64 `gorm:"column:package_id"`
	Package   *Package

	Versions        *[]AffectedVersion        `gorm:"foreignKey:AffectedID"`
	ExcludeVersions *[]AffectedExcludeVersion `gorm:"foreignKey:AffectedID"`
	Severities      *[]AffectedSeverity       `gorm:"foreignKey:AffectedID"`
	Range           *[]Range                  `gorm:"foreignKey:AffectedID"`

	// Digests that are known to correspond to this vulnerability, but cannot be closely associated with a package
	Digests *[]Digest `gorm:"many2many:affected_digests"`
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
//	Digests *[]Digest `gorm:"many2many:not_affected_digests"`
//}

// TODO: reuse existing Severities tables with many2many
type AffectedSeverity struct {
	ID         int64 `gorm:"column:id;primaryKey"`
	AffectedID int64 `gorm:"column:affected_id;not null"`

	Type     string  `gorm:"column:type;not null"`
	Score    string  `gorm:"column:score;not null"`
	Source   *string `gorm:"column:source"`
	Priority *string `gorm:"column:priority"` // TODO: naming is hard...
}

type AffectedVersion struct {
	ID         int64 `gorm:"column:id;primaryKey"`
	AffectedID int64 `gorm:"column:affected_id;not null"`

	Version string `gorm:"column:version;not null"`
}

type AffectedExcludeVersion struct {
	ID         int64 `gorm:"column:id;primaryKey"`
	AffectedID int64 `gorm:"column:affected_id;not null"`

	Version string `gorm:"column:version;not null"`
}

type Range struct {
	ID         int64 `gorm:"primaryKey"`
	AffectedID int64 `gorm:"column:affected_id;not null"`

	Type   string        `gorm:"column:type;not null"`
	Repo   *string       `gorm:"column:repo"`
	Events *[]RangeEvent `gorm:"many2many:range_range_events"`
}

type RangeEvent struct {
	ID int64 `gorm:"primaryKey"`

	Introduced   *string `gorm:"column:introduced;index:idx_range_event,unique"`
	Fixed        *string `gorm:"column:fixed;index:idx_range_event,unique"`
	LastAffected *string `gorm:"column:last_affected;index:idx_range_event,unique"`
	Limit        *string `gorm:"column:range_limit;index:idx_range_event,unique"` // limit is a keyword in sql, so it's easier to just use range_limit instead

	// non OSV...
	State string `gorm:"column:state;index:idx_range_event,unique"` // TODO: this could be db specific since there will be multiple ways to represent/interpret this

	// if deduplicating these, then this can't be associated
	//RangeEventMetadata *[]RangeEventMetadata `gorm:"foreignKey:RangeEventID"`
}

func (re *RangeEvent) BeforeCreate(tx *gorm.DB) (err error) {
	//tx = tx.Session(&gorm.Session{Logger: loggerIgnoreRecordNotFound{tx.Logger}})

	// if the event already exist in the table then we should not insert a new record
	var existing RangeEvent
	result := tx.Where("introduced = ? AND fixed = ? AND last_affected = ? AND range_limit = ? AND state = ?", re.Introduced, re.Fixed, re.LastAffected, re.Limit, re.State).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*re = existing
	}
	return nil
}

//type RangeEventMetadata struct {
//	ID           int64 `gorm:"primaryKey"`
//	RangeEventID int64 `gorm:"column:range_event_id;not null"`
//
//	GitCommit      *string `gorm:"column:git_commit"`
//	PullRequestURL *string `gorm:"column:pull_request_url"`
//	Timestamp      *string `gorm:"column:timestamp"`
//	// TODO: what else here?
//}

// primary package identifiers (search entrypoints)

type Cpe struct {
	// TODO: what about different CPE versions?

	ID int64 `gorm:"column:id;primaryKey"`

	Schema         string  `gorm:"column:schema;not null;index:idx_cpe"` // effectively the CPE version
	Type           string  `gorm:"column:type;not null;index:idx_cpe"`
	Vendor         *string `gorm:"column:vendor;index:idx_cpe"`
	Product        string  `gorm:"column:product;not null;index:idx_cpe"`
	Version        *string `gorm:"column:version;index:idx_cpe"`
	Update         *string `gorm:"column:version_update;index:idx_cpe"` // update is a SQL keyword
	TargetSoftware *string `gorm:"column:target_software;index:idx_cpe"`

	// TODO: should we also have the remaining CPE fields here?
}

func (c *Cpe) BeforeCreate(tx *gorm.DB) (err error) {
	// if the name, major version, and minor version already exist in the table then we should not insert a new record
	var existing Cpe
	result := tx.Where("schema = ? AND type = ? AND vendor = ? AND product = ? AND version = ? AND version_update = ? AND target_software = ?", c.Schema, c.Type, c.Vendor, c.Product, c.Version, c.Update, c.TargetSoftware).First(&existing)
	if result.Error == nil {
		// if the record already exists, then we should use the existing record
		*c = existing
	}
	return nil
}

// Digest represents arbitrary digests that can be associated with a vulnerability such that if found the material can be considered to be affected by this vulnerability
type Digest struct {
	ID int64 `gorm:"column:id;primaryKey"`

	Algorithm string `gorm:"column:algorithm;not null"`
	Value     string `gorm:"column:value;not null"`
}

type Package struct {
	// TODO: setup unique indexes only for writing and drop before shipping for the best size tradeoff

	ID int64 `gorm:"column:id;primaryKey"`

	// TODO: break purl out into fields here
	Ecosystem   string `gorm:"column:ecosystem"` // TODO: NVD doesn't have this, should this be nullable?
	PackageName string `gorm:"column:package_name;index:package_name"`

	OperatingSystemID *int64           `gorm:"column:operating_system_id"`
	OperatingSystem   *OperatingSystem `gorm:"foreignKey:OperatingSystemID"`

	Purls *[]Purl `gorm:"many2many:package_purls"`
	Cpes  *[]Cpe  `gorm:"many2many:package_cpes"`

	// Digests that are known to correspond to this package, either contained within, packaged for distribution, or normalized to a single file
	Digests *[]Digest `gorm:"many2many:package_digests"`

	// package qualifier info
	PackageQualifierPlatformCpes    *[]PackageQualifierPlatformCpe   `gorm:"foreignKey:PackageID"`
	PackageQualifierRpmModularities *[]PackageQualifierRpmModularity `gorm:"foreignKey:PackageID"` // TODO: shouldn't this be 1:1 (only a single module for a single package)
}

type Purl struct {
	ID int64 `gorm:"column:id;primaryKey"`

	Scheme    string  `gorm:"column:scheme"`
	Type      string  `gorm:"column:type"`
	Namespace *string `gorm:"column:namespace"`
	Name      string  `gorm:"column:name"`
	Version   string  `gorm:"column:version"`
	SubPath   *string `gorm:"column:subpath"`

	Qualifiers *[]Qualifier `gorm:"many2many:purl_qualifiers"`
}

// secondary package identifier information

type Qualifier struct {
	ID int64 `gorm:"column:id;primaryKey"`

	Key   string `gorm:"column:key"`
	Value string `gorm:"column:value"`
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

type PackageQualifierPlatformCpe struct {
	ID        int64 `gorm:"column:id;primaryKey"`
	PackageID int64 `gorm:"column:package_id;not null"`

	Cpe string `gorm:"column:cpe;not null"`
}

type PackageQualifierRpmModularity struct {
	ID        int64 `gorm:"column:id;primaryKey"`
	PackageID int64 `gorm:"column:package_id;not null"`

	Module string `gorm:"column:module;not null"`
}

// logical package info

type LogicalPackage struct {
	ID int64 `gorm:"column:id;primaryKey"`

	Packages []Package `gorm:"many2many:logical_package_packages"`
}

// aux

type DbMetadata struct {
	BuildTimestamp *time.Time `gorm:"column:build_timestamp;not null"`
	Model          int        `gorm:"column:model;not null"`
	Revision       int        `gorm:"column:revision;not null"`
	Addition       int        `gorm:"column:addition;not null"`
}

// TODO: this will probably be shipped as another DB and attached on as-needed basis
type Blob struct {
	Digest string `gorm:"column:digest;primaryKey"`
	Value  string `gorm:"column:value;not null"`
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
