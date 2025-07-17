package v6

import "strings"

// VulnerabilityStatus is meant to convey the current point in the lifecycle for a vulnerability record.
// This is roughly based on CVE status, NVD status, and vendor-specific status values (see https://nvd.nist.gov/vuln/vulnerability-status)
type VulnerabilityStatus string

const (
	UnknownVulnerabilityStatus VulnerabilityStatus = ""

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
	UnknownSeverityScheme SeverityScheme = ""

	// SeveritySchemeCVSS is the Common Vulnerability Scoring System severity scheme
	SeveritySchemeCVSS SeverityScheme = "CVSS"

	// SeveritySchemeHML is a string severity scheme (High, Medium, Low)
	SeveritySchemeHML SeverityScheme = "HML"

	// SeveritySchemeCHML is a string severity scheme (Critical, High, Medium, Low)
	SeveritySchemeCHML SeverityScheme = "CHML"

	// SeveritySchemeCHMLN is a string severity scheme (Critical, High, Medium, Low, Negligible)
	SeveritySchemeCHMLN SeverityScheme = "CHMLN"
)

// FixStatus conveys if the package is affected (or not) and the current availability (or not) of a fix
type FixStatus string

const (
	UnknownFixStatus FixStatus = ""

	// FixedStatus affirms the package is affected and a fix is available
	FixedStatus FixStatus = "fixed"

	// NotFixedStatus affirms the package is affected and a fix is not available
	NotFixedStatus FixStatus = "not-fixed"

	// WontFixStatus affirms the package is affected and a fix will not be provided
	WontFixStatus FixStatus = "wont-fix"

	// NotAffectedFixStatus affirms the package is not affected by the vulnerability
	NotAffectedFixStatus FixStatus = "not-affected"
)

const (
	// AdvisoryReferenceTag is a tag that can be used to identify vulnerability advisory URL references
	AdvisoryReferenceTag = "advisory"
)

func ParseVulnerabilityStatus(s string) VulnerabilityStatus {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case string(VulnerabilityActive), "":
		return VulnerabilityActive
	case string(VulnerabilityAnalyzing):
		return VulnerabilityAnalyzing
	case string(VulnerabilityRejected):
		return VulnerabilityRejected
	case string(VulnerabilityDisputed):
		return VulnerabilityDisputed
	default:
		return UnknownVulnerabilityStatus
	}
}

func ParseSeverityScheme(s string) SeverityScheme {
	switch replaceAny(strings.TrimSpace(strings.ToLower(s)), "", "-", "_", " ") {
	case strings.ToLower(string(SeveritySchemeCVSS)):
		return SeveritySchemeCVSS
	case strings.ToLower(string(SeveritySchemeHML)):
		return SeveritySchemeHML
	case strings.ToLower(string(SeveritySchemeCHML)):
		return SeveritySchemeCHML
	case strings.ToLower(string(SeveritySchemeCHMLN)):
		return SeveritySchemeCHMLN
	default:
		return UnknownSeverityScheme
	}
}

func ParseFixStatus(s string) FixStatus {
	switch replaceAny(strings.TrimSpace(strings.ToLower(s)), "-", " ", "_") {
	case string(FixedStatus):
		return FixedStatus
	case string(NotFixedStatus):
		return NotFixedStatus
	case string(WontFixStatus):
		return WontFixStatus
	case string(NotAffectedFixStatus):
		return NotAffectedFixStatus
	default:
		return UnknownFixStatus
	}
}

func NormalizeReferenceTags(tags []string) []string {
	var normalized []string
	for _, tag := range tags {
		normalized = append(normalized, replaceAny(strings.ToLower(strings.TrimSpace(tag)), "-", " ", "_"))
	}
	return normalized
}

func replaceAny(input string, newStr string, searchFor ...string) string {
	for _, s := range searchFor {
		input = strings.ReplaceAll(input, s, newStr)
	}
	return input
}
