package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGolangConstraints(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		satisfied  bool
	}{
		{
			name:       "regular semantic version satisfied",
			version:    "v1.2.3",
			constraint: "< 1.2.4",
			satisfied:  true,
		},
		{
			name:       "regular semantic version unsatisfied",
			version:    "v1.2.3",
			constraint: "> 1.2.4",
			satisfied:  false,
		},
		{
			name:       "+incompatible added to version", // see grype#1581
			version:    "v3.2.0+incompatible",
			constraint: "<=3.2.0",
			satisfied:  true,
		},
		{
			name:       "the empty constraint is always satisfied",
			version:    "v1.0.0",
			constraint: "",
			satisfied:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newGolangConstraint(tc.constraint)
			require.NoError(t, err)
			v, err := NewVersion(tc.version, GolangFormat)
			require.NoError(t, err)
			sat, err := c.Satisfied(v)
			require.NoError(t, err)
			assert.Equal(t, tc.satisfied, sat)
		})
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		expected   string
	}{
		{
			name:       "empty string",
			constraint: "",
			expected:   "none (go)",
		},
		{
			name:       "basic constraint",
			constraint: "< 1.3.4",
			expected:   "< 1.3.4 (go)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := newGolangConstraint(tc.constraint)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, c.String())
		})
	}
}
