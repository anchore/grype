package v6

import "time"

//type VulnerabilityBlob []struct {
//	Advisory struct {
//		Severity string `json:"severity"`
//	}
//}

type VulnerabilityStatus string

const (
	VulnerabilityNoStatus  VulnerabilityStatus = "?"
	VulnerabilityActive    VulnerabilityStatus = "active" // empty also means active
	VulnerabilityAnalyzing VulnerabilityStatus = "analyzing"
	// VulnerabilityWithdrawn VulnerabilityStatus = "withdrawn" // TODO: I can't seem to be able to find how to determine this vs rejected?
	VulnerabilityRejected VulnerabilityStatus = "rejected"
	VulnerabilityDisputed VulnerabilityStatus = "disputed"
)

type SeverityScheme string

const (
	SeveritySchemeCVSSV2 SeverityScheme = "CVSSv2"
	SeveritySchemeCVSSV3 SeverityScheme = "CVSSv3"
	SeveritySchemeHML    SeverityScheme = "HML"
	SeveritySchemeCHMLN  SeverityScheme = "CHMLN"
)

// TODO: add vulnerability match exclusions

type VulnerabilityBlob struct {
	ID string `json:"id"` // TODO: if indexed by this, should we include it in the model? or inflate the business object with it instead?

	// ProviderName of the Vunnel provider (or sub processor responsible for data records from a single specific source, e.g. "ubuntu")
	ProviderName string `json:"provider"`

	// List of names, email, or organizations who submitted the vulnerability
	Assigner []string `json:"assigner,omitempty"`

	// Description of the vulnerability as provided by the source
	Description string `json:"description"`

	// ModifiedDate is the date the vulnerability record was last modified
	ModifiedDate *time.Time `json:"modified,omitempty"`

	// PublishedDate is the date the vulnerability record was first published
	PublishedDate *time.Time `json:"published,omitempty"`

	// WithdrawnDate is the date the vulnerability record was withdrawn
	//WithdrawnDate *time.Time `json:"withdrawn,omitempty"` // TOOD: can't seem to be able to find this... only modified and published

	// Status convey the current status of the vulnerability
	Status VulnerabilityStatus `json:"status"`

	// References are URLs to external resources that provide more information about the vulnerability
	References []Reference `json:"refs,omitempty"`

	// Aliases is a list of IDs of the same vulnerability in other databases, in the form of the ID field. This allows one database to claim that its own entry describes the same vulnerability as one or more entries in other databases.
	Aliases []string `json:"aliases,omitempty"`

	// Severities is a list of severity indications (quantitative or qualitative) for the vulnerability
	Severities []Severity `json:"severities,omitempty"`
}

type Reference struct {
	// URL is the external resource
	URL string `json:"url"`

	// Tags is a free-form organizational field to convey additional information about the reference
	Tags []string `json:"tags,omitempty"`
}

// Severity represents a single severity record for a vulnerability
type Severity struct {
	// Type describes the quantitative method used to determine the Score, such as "CVSS_V3". Alternatively this makes
	// claim that Value is qualitative, for example "HML" (High, Medium, Low), CHMLN (critical-high-medium-low-negligible)
	Scheme SeverityScheme `json:"scheme"`

	// Value is the severity score (e.g. "7.5", "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",  or "high" )
	Value string `json:"value"`

	// Source is the name of the source of the severity score (e.g. "nvd@nist.gov" or "security-advisories@github.com")
	Source string `json:"source"`

	// Rank is a free-form organizational field to convey priority over other severities
	Rank int `json:"rank"`
}

type AffectedBlob struct {
	CVEs          []string        `json:"cves"`
	RpmModularity string          `json:"rpm_modularity,omitempty"`
	PlatformCPEs  []string        `json:"platform_cpes,omitempty"`
	Ranges        []AffectedRange `json:"ranges,omitempty"`
}

type NotAffectedBlob struct {
	CVEs          []string        `json:"cves"`
	RpmModularity string          `json:"rpm_modularity,omitempty"`
	PlatformCPEs  []string        `json:"platform_cpes,omitempty"`
	Ranges        []AffectedRange `json:"ranges,omitempty"`
}

type AffectedRange struct {
	Version AffectedVersion `json:"version"`
	Fix     *Fix            `json:"fix,omitempty"`
}

type Fix struct {
	Version string     `json:"version"`
	State   string     `json:"state"`
	Detail  *FixDetail `json:"detail,omitempty"`
}

type FixDetail struct {
	GitCommit  string      `json:"git_commit"`
	Timestamp  time.Time   `json:"timestamp"`
	References []Reference `json:"references,omitempty"`
}

type AffectedVersion struct {
	// Type is the type of version range, such as "semver", "rpm", "pypi", etc
	Type string `json:"type"`

	// Constraint allows for a version range expression, such as ">=1.0.0", "1.0.0", ">= 1.0, <2.0", etc
	Constraint string `json:"constraint"`
}

type EpssBlob struct {
	CVE        string // TODO: if indexed by this, should we include it in the model? or inflate the business object with it instead?
	EPSS       string
	Percentile string
	Date       time.Time
}

type KnownExploitedVulnerabilityBlob struct {
	CVE                        string // TODO: if indexed by this, should we include it in the model? or inflate the business object with it instead?
	VendorProject              string
	Product                    string
	DateAdded                  string
	RequiredAction             string
	DueDate                    string
	KnownRansomwareCampaignUse string
	Notes                      string
	References                 []string //parsed from Notes
}
