package v6

import (
	"encoding/json"
	"fmt"
	"time"
)

// VulnerabilityStatus is meant to convey the current point in the lifecycle for a vulnerability record.
// This is roughly based on CVE status, NVD status, and vendor-specific status values (see https://nvd.nist.gov/vuln/vulnerability-status)
type VulnerabilityStatus string

const (
	// VulnerabilityNoStatus is the default status for a vulnerability record
	VulnerabilityNoStatus VulnerabilityStatus = "?"

	// VulnerabilityActive means that the information from the vulnerability record is actionable
	VulnerabilityActive VulnerabilityStatus = "active" // empty also means active

	// VulnerabilityAnalyzing means that the vulnerability record is being reviewed, it may or may not be actionable
	VulnerabilityAnalyzing VulnerabilityStatus = "analyzing"

	// VulnerabilityRejected means that data from the vulnerability record should not be acted upon
	VulnerabilityRejected VulnerabilityStatus = "rejected"

	// VulnerabilityDisputed means that the vulnerability record is in contention, it may or may not be actionable
	VulnerabilityDisputed VulnerabilityStatus = "disputed"
)

// SeverityScheme represents how to interpret the string value for a vulnerability severity
type SeverityScheme string

const (
	// SeveritySchemeCVSS is the Common Vulnerability Scoring System severity scheme
	SeveritySchemeCVSS SeverityScheme = "CVSS"

	// SeveritySchemeHML is a string severity scheme (High, Medium, Low)
	SeveritySchemeHML SeverityScheme = "HML"

	// SeveritySchemeCHMLN is a string severity scheme (Critical, High, Medium, Low, Negligible)
	SeveritySchemeCHMLN SeverityScheme = "CHMLN"
)

// VulnerabilityBlob represents the core advisory record for a single known vulnerability from a specific provider.
type VulnerabilityBlob struct {
	// ID is the lowercase unique string identifier for the vulnerability relative to the provider
	ID string `json:"id"`

	// ProviderName of the Vunnel provider (or sub processor responsible for data records from a single specific source, e.g. "ubuntu")
	ProviderName string `json:"provider"`

	// Assigner is a list of names, email, or organizations who submitted the vulnerability
	Assigner []string `json:"assigner,omitempty"`

	// Status conveys the actionability of the current record
	Status VulnerabilityStatus `json:"status"`

	// Description of the vulnerability as provided by the source
	Description string `json:"description"`

	// PublishedDate is the date the vulnerability record was first published
	PublishedDate *time.Time `json:"published,omitempty"`

	// ModifiedDate is the date the vulnerability record was last modified
	ModifiedDate *time.Time `json:"modified,omitempty"`

	// WithdrawnDate is the date the vulnerability record was withdrawn
	WithdrawnDate *time.Time `json:"withdrawn,omitempty"`

	// References are URLs to external resources that provide more information about the vulnerability
	References []Reference `json:"refs,omitempty"`

	// Aliases is a list of IDs of the same vulnerability in other databases, in the form of the ID field. This allows one database to claim that its own entry describes the same vulnerability as one or more entries in other databases.
	Aliases []string `json:"aliases,omitempty"`

	// Severities is a list of severity indications (quantitative or qualitative) for the vulnerability
	Severities []Severity `json:"severities,omitempty"`
}

// Reference represents a single external URL and string tags to use for organizational purposes
type Reference struct {
	// URL is the external resource
	URL string `json:"url"`

	// Tags is a free-form organizational field to convey additional information about the reference
	Tags []string `json:"tags,omitempty"`
}

// Severity represents a single string severity record for a vulnerability record
type Severity struct {
	// Scheme describes the quantitative method used to determine the Score, such as "CVSS_V3". Alternatively this makes
	// claim that Value is qualitative, for example "HML" (High, Medium, Low), CHMLN (critical-high-medium-low-negligible)
	Scheme SeverityScheme `json:"scheme"`

	// Value is the severity score (e.g. "7.5", "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",  or "high" )
	Value any `json:"value"` // one of CVSSSeverity, HMLSeverity, CHMLNSeverity

	// Source is the name of the source of the severity score (e.g. "nvd@nist.gov" or "security-advisories@github.com")
	Source string `json:"source"`

	// Rank is a free-form organizational field to convey priority over other severities
	Rank int `json:"rank"`
}

type severityAlias Severity

type severityUnmarshalProxy struct {
	*severityAlias
	Value json.RawMessage `json:"value"`
}

// UnmarshalJSON custom unmarshaller for Severity struct
func (s *Severity) UnmarshalJSON(data []byte) error {
	aux := &severityUnmarshalProxy{
		severityAlias: (*severityAlias)(s),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	var cvss CVSSSeverity
	if err := json.Unmarshal(aux.Value, &cvss); err == nil && cvss.Vector != "" {
		s.Value = cvss
		return nil
	}

	var strSeverity string
	if err := json.Unmarshal(aux.Value, &strSeverity); err == nil {
		s.Value = strSeverity
		return nil
	}

	return fmt.Errorf("could not unmarshal severity value to known type: %s", aux.Value)
}

// CVSSSeverity represents a single Common Vulnerability Scoring System entry
type CVSSSeverity struct {
	// Vector is the CVSS assessment as a parameterized string
	Vector string `json:"vector"`

	// Version is the CVSS version (e.g. "3.0")
	Version string `json:"version"`

	// Score is the evaluated CVSS vector as a scalar between 0 and 10
	Score float64 `json:"score"`
}
