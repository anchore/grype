package match

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetails_Sorting(t *testing.T) {

	detailExactDirectHigh := Detail{
		Type:       ExactDirectMatch,
		Confidence: 0.9,
		SearchedBy: "attribute1",
		Found:      "value1",
		Matcher:    "matcher1",
	}
	detailExactDirectLow := Detail{
		Type:       ExactDirectMatch,
		Confidence: 0.5,
		SearchedBy: "attribute1",
		Found:      "value1",
		Matcher:    "matcher1",
	}
	detailExactIndirect := Detail{
		Type:       ExactIndirectMatch,
		Confidence: 0.7,
		SearchedBy: "attribute2",
		Found:      "value2",
		Matcher:    "matcher2",
	}
	detailCPEMatch := Detail{
		Type:       CPEMatch,
		Confidence: 0.8,
		SearchedBy: "attribute3",
		Found:      "value3",
		Matcher:    "matcher3",
	}

	tests := []struct {
		name     string
		details  Details
		expected Details
	}{
		{
			name: "sorts by type first, then by confidence",
			details: Details{
				detailCPEMatch,
				detailExactDirectHigh,
				detailExactIndirect,
				detailExactDirectLow,
			},
			expected: Details{
				detailExactDirectHigh,
				detailExactDirectLow,
				detailExactIndirect,
				detailCPEMatch,
			},
		},
		{
			name: "sorts by confidence within the same type",
			details: Details{
				detailExactDirectLow,
				detailExactDirectHigh,
			},
			expected: Details{
				detailExactDirectHigh,
				detailExactDirectLow,
			},
		},
		{
			name: "sorts by ID when type and confidence are the same",
			details: Details{
				// clone of detailExactDirectLow with slight difference to enforce ID sorting
				{
					Type:       ExactDirectMatch,
					Confidence: 0.5,
					SearchedBy: "attribute2",
					Found:      "value2",
					Matcher:    "matcher2",
				},
				detailExactDirectLow,
			},
			expected: Details{
				detailExactDirectLow,
				{
					Type:       ExactDirectMatch,
					Confidence: 0.5,
					SearchedBy: "attribute2",
					Found:      "value2",
					Matcher:    "matcher2",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Sort(tt.details)
			require.Equal(t, tt.expected, tt.details)
		})
	}
}

func TestHasExclusivelyAnyMatchTypes(t *testing.T) {
	tests := []struct {
		name     string
		details  Details
		types    []Type
		expected bool
	}{
		{
			name:     "all types allowed",
			details:  Details{{Type: "A"}, {Type: "B"}},
			types:    []Type{"A", "B"},
			expected: true,
		},
		{
			name:     "mixed types with disallowed",
			details:  Details{{Type: "A"}, {Type: "B"}, {Type: "C"}},
			types:    []Type{"A", "B"},
			expected: false,
		},
		{
			name:     "single allowed type",
			details:  Details{{Type: "A"}},
			types:    []Type{"A"},
			expected: true,
		},
		{
			name:     "empty details",
			details:  Details{},
			types:    []Type{"A"},
			expected: false,
		},
		{
			name:     "empty types list",
			details:  Details{{Type: "A"}},
			types:    []Type{},
			expected: false,
		},
		{
			name:     "no match with disallowed type",
			details:  Details{{Type: "C"}},
			types:    []Type{"A", "B"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasExclusivelyAnyMatchTypes(tt.details, tt.types...)
			assert.Equal(t, tt.expected, result)
		})
	}
}
