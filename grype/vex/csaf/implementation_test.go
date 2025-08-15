package csaf

import (
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"slices"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	vexStatus "github.com/anchore/grype/grype/vex/status"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_newerCurrentReleaseDateFirst(t *testing.T) {
	type dateIDPair struct {
		date string
		id   string
	}

	tests := []struct {
		name     string
		input    []dateIDPair
		expected []string
	}{
		{
			name: "simple sort newest first",
			input: []dateIDPair{
				{"2023-01-01T00:00:00Z", "doc1"},
				{"2024-01-01T00:00:00Z", "doc2"},
				{"2022-01-01T00:00:00Z", "doc3"},
			},
			expected: []string{"doc2", "doc1", "doc3"},
		},
		{
			name: "already sorted",
			input: []dateIDPair{
				{"2024-01-01T00:00:00Z", "doc1"},
				{"2023-01-01T00:00:00Z", "doc2"},
			},
			expected: []string{"doc1", "doc2"},
		},
		{
			name: "same dates maintain order",
			input: []dateIDPair{
				{"2023-01-01T00:00:00Z", "first"},
				{"2023-01-01T00:00:00Z", "second"},
			},
			expected: []string{"first", "second"},
		},
		{
			name: "nil dates go last",
			input: []dateIDPair{
				{"", "nil1"},
				{"2023-01-01T00:00:00Z", "valid1"},
				{"2024-01-01T00:00:00Z", "valid2"},
			},
			expected: []string{"valid2", "valid1", "nil1"},
		},
		{
			name: "multiple nils maintain order",
			input: []dateIDPair{
				{"", "nil1"},
				{"2023-01-01T00:00:00Z", "valid"},
				{"", "nil2"},
			},
			expected: []string{"valid", "nil1", "nil2"},
		},
		{
			name: "all nils",
			input: []dateIDPair{
				{"", "first"},
				{"", "second"},
				{"", "third"},
			},
			expected: []string{"first", "second", "third"},
		},
		{
			name: "invalid date format goes last",
			input: []dateIDPair{
				{"invalid-date", "bad"},
				{"2023-01-01T00:00:00Z", "good"},
			},
			expected: []string{"good", "bad"},
		},
		{
			name: "mix of nil invalid and valid",
			input: []dateIDPair{
				{"", "nil"},
				{"invalid", "bad"},
				{"2024-01-01T00:00:00Z", "new"},
				{"2023-01-01T00:00:00Z", "old"},
			},
			expected: []string{"new", "old", "nil", "bad"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advs := make(advisories, len(tt.input))
			for i, pair := range tt.input {
				var datePtr *string
				if pair.date == "" {
					datePtr = nil
				} else {
					datePtr = &pair.date
				}

				advs[i] = &csaf.Advisory{
					Document: &csaf.Document{
						Tracking: &csaf.Tracking{
							ID:                 (*csaf.TrackingID)(&pair.id),
							CurrentReleaseDate: datePtr,
						},
					},
				}
			}

			slices.SortStableFunc(advs, newerCurrentReleaseDateFirst)

			result := make([]string, len(advs))
			for i, adv := range advs {
				result[i] = string(*adv.Document.Tracking.ID)
			}

			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_matchingRule(t *testing.T) {
	tests := []struct {
		name            string
		ignoreRules     []match.IgnoreRule
		m               match.Match
		advMatch        *advisoryMatch
		allowedStatuses []vexStatus.Status
		expected        *match.IgnoreRule
	}{
		{
			name:        "no ignore rules, not_affected status with inline mitigations",
			ignoreRules: []match.IgnoreRule{}, // No existing ignore rules
			m: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{ID: "CVE-2023-1234"},
				},
				Package: pkg.Package{Name: "test-package"},
			},
			advMatch: &advisoryMatch{
				Vulnerability: &csaf.Vulnerability{
					CVE: func() *csaf.CVE { cve := csaf.CVE("CVE-2023-1234"); return &cve }(),
				},
				Status:    knownNotAffected, // CSAF status
				ProductID: "test-product-1",
			},
			allowedStatuses: vexStatus.IgnoreList(), // [Fixed, NotAffected]
			expected: &match.IgnoreRule{
				Namespace:        "vex",
				Vulnerability:    "CVE-2023-1234",
				VexJustification: "", // Will be empty since no flags/threats in this simple case
				VexStatus:        "not_affected",
			},
		},
		{
			name:        "no ignore rules, under_investigation status should return nil",
			ignoreRules: []match.IgnoreRule{}, // No existing ignore rules
			m: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{ID: "CVE-2023-5678"},
				},
				Package: pkg.Package{Name: "another-package"},
			},
			advMatch: &advisoryMatch{
				Vulnerability: &csaf.Vulnerability{
					CVE: func() *csaf.CVE { cve := csaf.CVE("CVE-2023-5678"); return &cve }(),
				},
				Status:    underInvestigation, // CSAF status
				ProductID: "test-product-2",
			},
			allowedStatuses: vexStatus.IgnoreList(), // [Fixed, NotAffected] - doesn't include UnderInvestigation
			expected:        nil,                    // Should return nil since under_investigation is not in allowed statuses
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchingRule(tt.ignoreRules, tt.m, tt.advMatch, tt.allowedStatuses)
			if tt.expected == nil {
				require.Nil(t, result)
				return
			}
			if d := cmp.Diff(*result, *tt.expected); d != "" {
				t.Errorf("mismatch (-want +got):\n%s", d)
			}
		})
	}
}
