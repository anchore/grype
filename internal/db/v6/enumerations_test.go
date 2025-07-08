package v6

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVulnerabilityStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected VulnerabilityStatus
	}{
		{"Active status", "active", VulnerabilityActive},
		{"Analyzing status with whitespace", " analyzing ", VulnerabilityAnalyzing},
		{"Rejected status in uppercase", "REJECTED", VulnerabilityRejected},
		{"Disputed status", "disputed", VulnerabilityDisputed},
		{"Unknown status", "unknown", UnknownVulnerabilityStatus},
		{"Empty string as active status", "", VulnerabilityActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseVulnerabilityStatus(tt.input))
		})
	}
}

func TestParseSeverityScheme(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected SeverityScheme
	}{
		{"CVSS scheme", "Cvss", SeveritySchemeCVSS},
		{"HML scheme", "H-M-l", SeveritySchemeHML},
		{"CHML scheme", "ChmL", SeveritySchemeCHML},
		{"CHMLN scheme", "CHmLN", SeveritySchemeCHMLN},
		{"Unknown scheme", "unknown", UnknownSeverityScheme},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseSeverityScheme(tt.input))
		})
	}
}

func TestParseFixStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected FixStatus
	}{
		{"Fixed status", "fixed", FixedStatus},
		{"Not fixed status with hyphen", "not-fixed", NotFixedStatus},
		{"Wont fix status in uppercase with underscore", "WONT_FIX", WontFixStatus},
		{"Not affected status with whitespace", " not affected ", NotAffectedFixStatus},
		{"Unknown status", "unknown", UnknownFixStatus},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ParseFixStatus(tt.input))
		})
	}
}

func TestReplaceAny(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		newStr    string
		searchFor []string
		expected  string
	}{
		{"go case", "really not_fixed-i'promise", "-", []string{"'", " ", "_"}, "really-not-fixed-i-promise"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, replaceAny(tt.input, tt.newStr, tt.searchFor...))
		})
	}
}
