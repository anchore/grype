package versionutil

import "testing"

func TestEnforceSemVerConstraint(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{
			value:    " >=  5.0.0<7.1 ",
			expected: ">=5.0.0,<7.1",
		},
		{
			// already comma separated, which is how GHSA writes ranges. Without excluding
			// commas from the clause pattern this comes back as ">=1.0.0,,<2.0.0".
			value:    ">= 1.0.0, < 2.0.0",
			expected: ">=1.0.0,<2.0.0",
		},
		{
			value:    "None",
			expected: "",
		},
		{
			value:    "",
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			actual := EnforceSemVerConstraint(test.value)
			if actual != test.expected {
				t.Errorf("mismatch: '%s'!='%s'", actual, test.expected)
			}
		})
	}
}
