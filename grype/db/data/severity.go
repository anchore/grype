package data

import "strings"

type Severity string

const (
	SeverityUnknown    Severity = "Unknown"
	SeverityNegligible Severity = "Negligible"
	SeverityLow        Severity = "Low"
	SeverityMedium     Severity = "Medium"
	SeverityHigh       Severity = "High"
	SeverityCritical   Severity = "Critical"
)

func ParseSeverity(s string) Severity {
	clean := strings.TrimSpace(strings.ToLower(s))
	switch clean {
	case "unknown", "":
		return SeverityUnknown
	case "negligible":
		return SeverityNegligible
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}
