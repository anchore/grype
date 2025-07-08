package data

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	v6 "github.com/anchore/grype/internal/db/v6"
)

func TestFillInMissingSeverity(t *testing.T) {
	tests := []struct {
		name              string
		handle            *v6.VulnerabilityHandle
		severityCache     map[string]v6.Severity
		expected          []v6.Severity
		expectCacheUpdate bool
	}{
		{
			name:          "nil handle",
			handle:        nil,
			severityCache: map[string]v6.Severity{},
			expected:      nil,
		},
		{
			name: "nil metadata",
			handle: &v6.VulnerabilityHandle{
				BlobValue: nil,
			},
			severityCache: map[string]v6.Severity{},
			expected:      nil,
		},
		{
			name: "non-CVE ID",
			handle: &v6.VulnerabilityHandle{
				BlobValue: &v6.VulnerabilityBlob{
					ID: "GHSA-123",
					Severities: []v6.Severity{
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]v6.Severity{},
			expected:      []v6.Severity{{Value: "high"}},
		},
		{
			name: "NVD provider with CVE",
			handle: &v6.VulnerabilityHandle{
				ProviderID: "nvd",
				BlobValue: &v6.VulnerabilityBlob{
					ID: "CVE-2023-1234",
					Severities: []v6.Severity{
						{Value: "critical"},
					},
				},
			},
			severityCache:     map[string]v6.Severity{},
			expected:          []v6.Severity{{Value: "critical"}},
			expectCacheUpdate: true,
		},
		{
			name: "CVE with existing severities",
			handle: &v6.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &v6.VulnerabilityBlob{
					ID: "CVE-2023-5678",
					Severities: []v6.Severity{
						{Value: "medium"},
						{Value: "high"},
					},
				},
			},
			severityCache: map[string]v6.Severity{
				"cve-2023-5678": {Value: "critical"},
			},
			expected: []v6.Severity{
				{Value: "medium"},
				{Value: "high"},
			},
		},
		{
			name: "CVE with no severities, using cache",
			handle: &v6.VulnerabilityHandle{
				ProviderID: "github",
				BlobValue: &v6.VulnerabilityBlob{
					ID:         "CVE-2023-9012",
					Severities: []v6.Severity{},
				},
			},
			severityCache: map[string]v6.Severity{
				"cve-2023-9012": {Value: "high"},
			},
			expected: []v6.Severity{{Value: "high"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &writer{
				severityCache: tt.severityCache,
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					assert.NotContains(t, tt.severityCache, strings.ToLower(tt.handle.BlobValue.ID))
				}
			}

			w.fillInMissingSeverity(tt.handle)

			if tt.handle == nil || tt.handle.BlobValue == nil {
				return
			}

			if tt.expectCacheUpdate {
				// assert expected ids are not in the cache
				if tt.handle != nil && tt.handle.BlobValue != nil {
					id := strings.ToLower(tt.handle.BlobValue.ID)
					assert.Equal(t, tt.severityCache[id], w.severityCache[id])
				}
			}

			assert.Equal(t, tt.expected, tt.handle.BlobValue.Severities)
		})
	}
}

func TestFilterUnknownSeverities(t *testing.T) {
	tests := []struct {
		name     string
		input    []v6.Severity
		expected []v6.Severity
	}{
		{
			name:     "empty input",
			input:    []v6.Severity{},
			expected: nil,
		},
		{
			name: "all known severities",
			input: []v6.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
			expected: []v6.Severity{
				{Value: "critical"},
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "mix of known and unknown",
			input: []v6.Severity{
				{Value: "high"},
				{Value: "unknown"},
				{Value: "medium"},
				{Value: ""},
			},
			expected: []v6.Severity{
				{Value: "high"},
				{Value: "medium"},
			},
		},
		{
			name: "non-string values",
			input: []v6.Severity{
				{Value: 5},
				{Value: nil},
				{Value: "high"},
			},
			expected: []v6.Severity{
				{Value: 5},
				{Value: "high"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterUnknownSeverities(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsKnownSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity v6.Severity
		expected bool
	}{
		{
			name:     "empty string",
			severity: v6.Severity{Value: ""},
			expected: false,
		},
		{
			name:     "unknown string",
			severity: v6.Severity{Value: "unknown"},
			expected: false,
		},
		{
			name:     "case insensitive",
			severity: v6.Severity{Value: "UNKNOWN"},
			expected: false,
		},
		{
			name:     "valid string severity",
			severity: v6.Severity{Value: "high"},
			expected: true,
		},
		{
			name:     "nil value",
			severity: v6.Severity{Value: nil},
			expected: false,
		},
		{
			name:     "numeric value",
			severity: v6.Severity{Value: 7},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isKnownSeverity(tt.severity)
			assert.Equal(t, tt.expected, result)
		})
	}
}
