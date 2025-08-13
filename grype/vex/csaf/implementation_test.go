package csaf

import (
	"slices"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
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
