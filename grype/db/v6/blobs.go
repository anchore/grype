package v6

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// VulnerabilityBlob represents the core advisory record for a single known vulnerability from a specific provider.
type VulnerabilityBlob struct {
	// ID is the lowercase unique string identifier for the vulnerability relative to the provider
	ID string `json:"id"`

	// Assigners is a list of names, email, or organizations who submitted the vulnerability
	Assigners []string `json:"assigner,omitempty"`

	// Description of the vulnerability as provided by the source
	Description string `json:"description,omitempty"`

	// References are URLs to external resources that provide more information about the vulnerability
	References []Reference `json:"refs,omitempty"`

	// Aliases is a list of IDs of the same vulnerability in other databases, in the form of the ID field. This allows one database to claim that its own entry describes the same vulnerability as one or more entries in other databases.
	Aliases []string `json:"aliases,omitempty"`

	// Severities is a list of severity indications (quantitative or qualitative) for the vulnerability
	Severities []Severity `json:"severities,omitempty"`
}

func (v VulnerabilityBlob) String() string {
	return v.ID
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
	Source string `json:"source,omitempty"`

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
	Version string `json:"version,omitempty"`
}

func (c CVSSSeverity) String() string {
	vector := c.Vector
	if !strings.HasPrefix(strings.ToLower(c.Vector), "cvss:") && c.Version != "" {
		vector = fmt.Sprintf("CVSS:%s/%s", c.Version, c.Vector)
	}
	return vector
}

// AffectedPackageBlob represents a package affected by a vulnerability.
type AffectedPackageBlob struct {
	// CVEs is a list of Common Vulnerabilities and Exposures (CVE) identifiers related to this vulnerability.
	CVEs []string `json:"cves,omitempty"`

	// Qualifiers are package attributes that confirm the package is affected by the vulnerability.
	Qualifiers *AffectedPackageQualifiers `json:"qualifiers,omitempty"`

	// Ranges specifies the affected version ranges and fixes if available.
	Ranges []AffectedRange `json:"ranges,omitempty"`
}

func (a AffectedPackageBlob) String() string {
	var fields []string

	if len(a.Ranges) > 0 {
		var ranges []string
		for _, r := range a.Ranges {
			ranges = append(ranges, r.String())
		}
		fields = append(fields, fmt.Sprintf("ranges=%s", strings.Join(ranges, ", ")))
	}

	if len(a.CVEs) > 0 {
		fields = append(fields, fmt.Sprintf("cves=%s", strings.Join(a.CVEs, ", ")))
	}

	return strings.Join(fields, ", ")
}

// AffectedPackageQualifiers contains package attributes that confirm the package is affected by the vulnerability.
type AffectedPackageQualifiers struct {
	// RpmModularity indicates if the package follows RPM modularity for versioning.
	RpmModularity *string `json:"rpm_modularity,omitempty"`

	// PlatformCPEs lists Common Platform Enumeration (CPE) identifiers for affected platforms.
	PlatformCPEs []string `json:"platform_cpes,omitempty"`
}

// AffectedRange defines a specific range of versions affected by a vulnerability.
type AffectedRange struct {
	// Version defines the version constraints for affected software.
	Version AffectedVersion `json:"version,omitempty"`

	// Fix provides details on the fix version and its state if available.
	Fix *Fix `json:"fix,omitempty"`
}

func (a AffectedRange) String() string {
	return fmt.Sprintf("%s (%s)", a.Version, a.Fix)
}

// Fix conveys availability of a fix for a vulnerability.
type Fix struct {
	// Version is the version number of the fix.
	Version string `json:"version,omitempty"`

	// State represents the status of the fix (e.g., "fixed", "unaffected").
	State FixStatus `json:"state,omitempty"`

	// Detail provides additional fix information, such as commit details.
	Detail *FixDetail `json:"detail,omitempty"`
}

func (f Fix) String() string {
	switch f.State {
	case FixedStatus:
		return fmt.Sprintf("fixed in %s", f.Version)
	case NotAffectedFixStatus:
		return fmt.Sprintf("%s is not affected", f.Version)
	}
	return string(f.State)
}

// FixDetail is additional information about a fix, such as commit details and patch URLs.
type FixDetail struct {
	// GitCommit is the identifier for the Git commit associated with the fix.
	GitCommit string `json:"git_commit,omitempty"`

	// Timestamp is the date and time when the fix was committed.
	Timestamp *time.Time `json:"timestamp,omitempty"`

	// References contains URLs or identifiers for additional resources on the fix.
	References []Reference `json:"references,omitempty"`
}

// AffectedVersion defines the versioning format and constraints.
type AffectedVersion struct {
	// Type specifies the versioning system used (e.g., "semver", "rpm").
	Type string `json:"type,omitempty"`

	// Constraint defines the version range constraint for affected versions.
	Constraint string `json:"constraint,omitempty"`
}

type KnownExploitedVulnerabilityBlob struct {
	Cve                        string     `json:"cve"`
	VendorProject              string     `json:"vendor_project,omitempty"`
	Product                    string     `json:"product,omitempty"`
	DateAdded                  *time.Time `json:"date_added,omitempty"`
	RequiredAction             string     `json:"required_action,omitempty"`
	DueDate                    *time.Time `json:"due_date,omitempty"`
	KnownRansomwareCampaignUse string     `json:"known_ransomware_campaign_use,omitempty"`
	Notes                      string     `json:"notes,omitempty"`
	URLs                       []string   `json:"urls,omitempty"`
	CWEs                       []string   `json:"cwes,omitempty"`
}
