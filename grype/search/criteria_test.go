package search

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/vulnerability"
)

func Test_CriteriaIterator(t *testing.T) {
	name1 := ByPackageName("name1")
	name2 := ByPackageName("name2")
	name3 := ByPackageName("name3")

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
			in:       []vulnerability.Criteria{Or(name1, name2)},
			expected: [][]vulnerability.Criteria{{name1}, {name2}},
		},
		{
			name:     "name1 AND (name2 or name3)",
			in:       []vulnerability.Criteria{name1, Or(name2, name3)},
			expected: [][]vulnerability.Criteria{{name1, name2}, {name1, name3}},
		},
		{
			name: "name1 AND (name2 or name3) AND (name1 or name2 or name3)",
			in:   []vulnerability.Criteria{name1, Or(name2, name3), Or(name1, name2, name3)},
			expected: [][]vulnerability.Criteria{
				{name1, name2, name1}, {name1, name3, name1},
				{name1, name2, name2}, {name1, name3, name2},
				{name1, name2, name3}, {name1, name3, name3},
			},
		},
		{
			name: "(name1 AND name2) OR (name1 AND name3)",
			in:   []vulnerability.Criteria{Or(And(name1, name2), And(name1, name3))},
			expected: [][]vulnerability.Criteria{
				{name1, name2}, {name1, name3},
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

func Test_ValidateCriteria(t *testing.T) {
	tests := []struct {
		name    string
		in      []vulnerability.Criteria
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "no error",
			in:      []vulnerability.Criteria{ByPackageName("steve"), ByDistro(distro.Distro{})},
			wantErr: require.NoError,
		},
		{
			name:    "package name error",
			in:      []vulnerability.Criteria{ByPackageName("steve"), ByPackageName("bob")},
			wantErr: require.Error,
		},
		{
			name:    "multiple distros error",
			in:      []vulnerability.Criteria{ByDistro(distro.Distro{}), ByDistro(distro.Distro{})},
			wantErr: require.Error,
		},
		{
			name:    "multiple package name in or condition not error",
			in:      []vulnerability.Criteria{Or(ByPackageName("steve"), ByPackageName("bob"))},
			wantErr: require.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCriteria(test.in)
			test.wantErr(t, err)
		})
	}
}
