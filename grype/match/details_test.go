package match

import (
	"math"
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

// TestDetails_rank covers the ranking Match.Merge uses to decide which of two records for the
// same finding describes it -- the successor to the direct-supersedes-indirect rules that used to
// live in Matches.Add.
func TestDetails_rank(t *testing.T) {
	tests := []struct {
		name     string
		details  Details
		expected int
	}{
		{
			name:     "direct is the strongest",
			details:  Details{{Type: ExactDirectMatch}},
			expected: 1,
		},
		{
			name:     "indirect ranks below direct",
			details:  Details{{Type: ExactIndirectMatch}},
			expected: 2,
		},
		{
			name:     "CPE ranks below indirect",
			details:  Details{{Type: CPEMatch}},
			expected: 3,
		},
		{
			name:     "the strongest detail in the set wins",
			details:  Details{{Type: CPEMatch}, {Type: ExactDirectMatch}, {Type: ExactIndirectMatch}},
			expected: 1,
		},
		{
			name:     "unrecognized types do not contribute",
			details:  Details{{Type: "made-up"}, {Type: CPEMatch}},
			expected: 3,
		},
		{
			name:     "no recognized type ranks last",
			details:  Details{{Type: "made-up"}},
			expected: math.MaxInt,
		},
		{
			name:     "no details rank last",
			details:  Details{},
			expected: math.MaxInt,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.details.rank())
		})
	}
}

// TestMergeDetails covers the guarantee that a match never carries the same detail twice: exact
// duplicates are dropped both across the sets being merged and within each one.
func TestMergeDetails(t *testing.T) {
	direct := Detail{Type: ExactDirectMatch, SearchedBy: "attr1", Found: "value1", Matcher: "matcher1"}
	cpe := Detail{Type: CPEMatch, SearchedBy: "attr2", Found: "value2", Matcher: "matcher2"}
	otherCPE := Detail{Type: CPEMatch, SearchedBy: "attr3", Found: "value2", Matcher: "matcher2"}

	tests := []struct {
		name     string
		sets     []Details
		expected Details
	}{
		{
			name:     "duplicates within a single set",
			sets:     []Details{{cpe, cpe}},
			expected: Details{cpe},
		},
		{
			name:     "duplicates across sets",
			sets:     []Details{{cpe}, {cpe}},
			expected: Details{cpe},
		},
		{
			name:     "duplicates on both sides",
			sets:     []Details{{cpe, cpe}, {cpe, cpe}},
			expected: Details{cpe},
		},
		{
			name: "details that differ are all kept, sorted strongest first",
			sets: []Details{{cpe, otherCPE}, {direct, cpe}},
			// direct sorts ahead of the CPE details
			expected: Details{direct, cpe, otherCPE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDetails(tt.sets...)
			assert.Equal(t, tt.expected[0], got[0], "strongest detail should sort first")
			assert.ElementsMatch(t, tt.expected, got)
		})
	}
}
