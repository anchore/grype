package search

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/vulnerability"
)

func Test_CriteriaIterator(t *testing.T) {
	name1 := ByPackageName("name1")
	name2 := ByPackageName("name2")
	name3 := ByPackageName("name3")

	name1orName2 := NewOrCriteria(name1, name2)
	name2orName3 := NewOrCriteria(name2, name3)
	name1orName2orName3 := NewOrCriteria(name1, name2, name3)

	tests := []struct {
		name     string
		in       []vulnerability.Criteria
		expected [][]vulnerability.Criteria
	}{
		{
			name:     "empty",
			in:       nil,
			expected: nil,
		},
		{
			name:     "one",
			in:       []vulnerability.Criteria{name1},
			expected: [][]vulnerability.Criteria{{name1}},
		},
		{
			name:     "name1 or name2",
			in:       []vulnerability.Criteria{name1orName2},
			expected: [][]vulnerability.Criteria{{name1}, {name2}},
		},
		{
			name:     "name1 AND (name2 or name3)",
			in:       []vulnerability.Criteria{name1, name2orName3},
			expected: [][]vulnerability.Criteria{{name1, name2}, {name1, name3}},
		},
		{
			name: "name1 AND (name2 or name3) AND (name1 or name2 or name3)",
			in:   []vulnerability.Criteria{name1, name2orName3, name1orName2orName3},
			expected: [][]vulnerability.Criteria{
				{name1, name2, name1}, {name1, name3, name1},
				{name1, name2, name2}, {name1, name3, name2},
				{name1, name2, name3}, {name1, name3, name3},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got [][]vulnerability.Criteria
			for _, row := range CriteriaIterator(test.in) {
				got = append(got, row)
			}
			require.ElementsMatch(t, test.expected, got)
		})
	}
}
