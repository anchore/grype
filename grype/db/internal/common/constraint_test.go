package common

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
