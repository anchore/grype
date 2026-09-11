package nvd

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestCvssSummariesSorted(t *testing.T) {
	tests := []struct {
		name     string
		input    CvssSummaries
		expected CvssSummaries
	}{
		{
			name: "primary types sorted by version descending",
			input: CvssSummaries{
				{Type: Primary, Version: "2.0", Source: "same-source"},
				{Type: Primary, Version: "3.1", Source: "same-source"},
				{Type: Primary, Version: "3.0", Source: "same-source"},
				{Type: Primary, Version: "4.0", Source: "same-source"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "4.0", Source: "same-source"},
				{Type: Primary, Version: "3.1", Source: "same-source"},
				{Type: Primary, Version: "3.0", Source: "same-source"},
				{Type: Primary, Version: "2.0", Source: "same-source"},
			},
		},
		{
			name: "secondary types sorted by version descending",
			input: CvssSummaries{
				{Type: Secondary, Version: "2.0", Source: "same-source"},
				{Type: Secondary, Version: "3.1", Source: "same-source"},
				{Type: Secondary, Version: "3.0", Source: "same-source"},
			},
			expected: CvssSummaries{
				{Type: Secondary, Version: "3.1", Source: "same-source"},
				{Type: Secondary, Version: "3.0", Source: "same-source"},
				{Type: Secondary, Version: "2.0", Source: "same-source"},
			},
		},
		{
			name: "primary types before secondary types",
			input: CvssSummaries{
				{Type: Secondary, Version: "3.1", Source: "G"},
				{Type: Primary, Version: "2.0", Source: "H"},
				{Type: Secondary, Version: "2.0", Source: "I"},
				{Type: Primary, Version: "3.0", Source: "J"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "2.0", Source: "H"},
				{Type: Primary, Version: "3.0", Source: "J"},
				{Type: Secondary, Version: "3.1", Source: "G"},
				{Type: Secondary, Version: "2.0", Source: "I"},
			},
		},
		{
			name: "mix of versions and types",
			input: CvssSummaries{
				{Type: Secondary, Version: "3.1", Source: "K"},
				{Type: Primary, Version: "3.1", Source: "L"},
				{Type: Primary, Version: "2.0", Source: "M"},
				{Type: Secondary, Version: "2.0", Source: "N"},
				{Type: Primary, Version: "3.0", Source: "O"},
				{Type: Secondary, Version: "3.0", Source: "P"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.1", Source: "L"},
				{Type: Primary, Version: "2.0", Source: "M"},
				{Type: Primary, Version: "3.0", Source: "O"},
				{Type: Secondary, Version: "3.1", Source: "K"},
				{Type: Secondary, Version: "2.0", Source: "N"},
				{Type: Secondary, Version: "3.0", Source: "P"},
			},
		},
		{
			name: "nvd source preferred within same type and version",
			input: CvssSummaries{
				{Type: Primary, Version: "3.0", Source: "random-source"},
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "random-source"},
			},
		},
		{
			name: "nvd source preferred but type takes precedence",
			input: CvssSummaries{
				{Type: Secondary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "random-source"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.0", Source: "random-source"},
				{Type: Secondary, Version: "3.0", Source: "nvd@nist.gov"},
			},
		},
		{
			name: "multiple nvd sources sorted by version",
			input: CvssSummaries{
				{Type: Primary, Version: "2.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.1", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.1", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "2.0", Source: "nvd@nist.gov"},
			},
		},
		{
			name: "complex sorting with types, versions, and sources",
			input: CvssSummaries{
				{Type: Secondary, Version: "3.1", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "2.0", Source: "random-source"},
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "other-source"},
				{Type: Secondary, Version: "2.0", Source: "other-source"},
				{Type: Secondary, Version: "3.0", Source: "nvd@nist.gov"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "other-source"},
				{Type: Primary, Version: "2.0", Source: "random-source"},
				{Type: Secondary, Version: "3.1", Source: "nvd@nist.gov"},
				{Type: Secondary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Secondary, Version: "2.0", Source: "other-source"},
			},
		},
		{
			name:     "empty input",
			input:    CvssSummaries{},
			expected: CvssSummaries{},
		},
		{
			name: "invalid version handling",
			input: CvssSummaries{
				{Type: Primary, Version: "invalid", Source: "Q"},
				{Type: Primary, Version: "3.0", Source: "R"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "invalid", Source: "Q"}, // sorted by source (Q < R)
				{Type: Primary, Version: "3.0", Source: "R"},
			},
		},
		{
			name: "source takes priority over version, then version as tiebreaker",
			input: CvssSummaries{
				{Type: Primary, Version: "4.0", Source: "other-source"},
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "2.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "3.0", Source: "source-a"},
			},
			expected: CvssSummaries{
				{Type: Primary, Version: "3.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "2.0", Source: "nvd@nist.gov"},
				{Type: Primary, Version: "4.0", Source: "other-source"},
				{Type: Primary, Version: "3.0", Source: "source-a"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.input.Sorted()

			if d := cmp.Diff(tc.expected, result, cmpopts.IgnoreUnexported(CvssSummary{})); d != "" {
				t.Errorf("unexpected result (-want +got):\n%s", d)
			}
		})
	}
}

func TestCvssSummaryVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"4.0", "4.0.0"},
		{"3.1", "3.1.0"},
		{"3.0", "3.0.0"},
		{"2.0", "2.0.0"},
		{"invalid", "2.0.0"}, // default to 2.0 for invalid versions
		{"3.1.5", "3.1.5"},
		{"", "2.0.0"}, // empty string is invalid
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			summary := CvssSummary{Version: tc.input}
			version := summary.version()
			if version.String() != tc.expected {
				t.Errorf("Expected version %s, got %s", tc.expected, version.String())
			}
		})
	}
}

func TestCveItem_CveTags_UnmarshalJSON(t *testing.T) {
	// this payload shape matches the documented NVD API schema
	// (https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema) and the real-world
	// CVE-2001-1517 record, which carries a disputed cveTag independently of vulnStatus.
	tests := []struct {
		name             string
		payload          string
		expectedTags     []CveTag
		expectedDisputed bool
	}{
		{
			name: "cveTags with a disputed tag decodes and is disputed",
			payload: `{
				"id": "CVE-2001-1517",
				"vulnStatus": "Deferred",
				"descriptions": [],
				"references": [],
				"cveTags": [
					{
						"sourceIdentifier": "cve@mitre.org",
						"tags": ["disputed"]
					}
				]
			}`,
			expectedTags: []CveTag{
				{SourceIdentifier: "cve@mitre.org", Tags: []string{"disputed"}},
			},
			expectedDisputed: true,
		},
		{
			name: "no cveTags decodes to nil and is not disputed",
			payload: `{
				"id": "CVE-2023-12345",
				"vulnStatus": "Analyzed",
				"descriptions": [],
				"references": []
			}`,
			expectedTags:     nil,
			expectedDisputed: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var item CveItem
			if err := json.Unmarshal([]byte(tc.payload), &item); err != nil {
				t.Fatalf("failed to unmarshal CveItem: %v", err)
			}

			if d := cmp.Diff(tc.expectedTags, item.CveTags); d != "" {
				t.Errorf("unexpected CveTags (-want +got):\n%s", d)
			}

			if actual := item.IsDisputed(); actual != tc.expectedDisputed {
				t.Errorf("IsDisputed() = %v, want %v", actual, tc.expectedDisputed)
			}
		})
	}
}
