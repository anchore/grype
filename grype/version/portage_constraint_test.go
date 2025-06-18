package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionPortageConstraint(t *testing.T) {
	tests := []testCase{
		// empty constraint is always satisfied
		{version: "1.2.3", constraint: "", satisfied: true},
		{version: "1.2.3-r1", constraint: "", satisfied: true},
		{version: "1.2.3_alpha1", constraint: "", satisfied: true},

		// simple equality
		{version: "1.2.3", constraint: "= 1.2.3", satisfied: true},
		{version: "1.2.3-r1", constraint: "= 1.2.3-r1", satisfied: true},
		{version: "1.2.3", constraint: "= 1.2.4", satisfied: false},

		// less than
		{version: "1.2.3", constraint: "< 1.2.4", satisfied: true},
		{version: "1.2.3", constraint: "< 1.2.3", satisfied: false},
		{version: "1.2.3", constraint: "< 1.2.2", satisfied: false},
		{version: "1.2.3-r1", constraint: "< 1.2.3-r2", satisfied: true},
		{version: "1.2.3-r2", constraint: "< 1.2.3-r1", satisfied: false},

		// less than or equal
		{version: "1.2.3", constraint: "<= 1.2.3", satisfied: true},
		{version: "1.2.3", constraint: "<= 1.2.4", satisfied: true},
		{version: "1.2.3", constraint: "<= 1.2.2", satisfied: false},
		{version: "1.2.3-r1", constraint: "<= 1.2.3-r1", satisfied: true},

		// greater than
		{version: "1.2.4", constraint: "> 1.2.3", satisfied: true},
		{version: "1.2.3", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.2", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.3-r2", constraint: "> 1.2.3-r1", satisfied: true},
		{version: "1.2.3-r1", constraint: "> 1.2.3-r2", satisfied: false},

		// greater than or equal
		{version: "1.2.3", constraint: ">= 1.2.3", satisfied: true},
		{version: "1.2.4", constraint: ">= 1.2.3", satisfied: true},
		{version: "1.2.2", constraint: ">= 1.2.3", satisfied: false},
		{version: "1.2.3-r1", constraint: ">= 1.2.3-r1", satisfied: true},

		// compound conditions with AND (comma)
		{version: "1.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.2.3-r5", constraint: ">= 1.2.3-r1, <= 1.2.3-r10", satisfied: true},

		// compound conditions with OR
		{version: "0.5.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: true},
		{version: "3.0.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: true},
		{version: "1.5.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: false},

		// complex compound conditions
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.3.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.8.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},

		// portage-specific version features
		// letter suffixes (a, b, c etc.)
		{version: "1.2a", constraint: "< 1.2b", satisfied: true},
		{version: "1.2b", constraint: "< 1.2a", satisfied: false},
		{version: "12.2.5", constraint: "> 12.2b", satisfied: true},

		// revision numbers (-r suffix)
		{version: "1.0.0-r1", constraint: "> 1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "> 1.0.0-r1", satisfied: false},
		{version: "1.2.3-r2", constraint: "> 1.2.3-r1", satisfied: true},
		{version: "1.2.3-r1", constraint: "< 1.2.3-r2", satisfied: true},

		// version suffixes (alpha, beta, pre, rc, p)
		{version: "1.0.0_alpha1", constraint: "< 1.0.0_beta1", satisfied: true},
		{version: "1.0.0_beta1", constraint: "< 1.0.0_rc1", satisfied: true},
		{version: "1.0.0_rc1", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "< 1.0.0_p1", satisfied: true},
		{version: "1.0.0_pre1", constraint: "> 1.0.0_alpha1", satisfied: true},

		// patch level suffixes
		{version: "1_p1", constraint: "> 1_p0", satisfied: true},
		{version: "1_p0", constraint: "> 1", satisfied: true},

		// decimal versions with leading zeros
		{version: "1.01", constraint: "< 1.1", satisfied: true},
		{version: "1.1", constraint: "> 1.01", satisfied: true},

		// version with missing patch components
		{version: "12.2", constraint: "< 12.2.0", satisfied: true}, // 12.2 < 12.2.0 is true in portage 🤯
		{version: "12.2.0", constraint: "> 12.2", satisfied: true},

		// edge cases - versions that should not match
		{version: "1.2.3", constraint: "= 1.2.4", satisfied: false},
		{version: "1.2.3", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.3", constraint: "< 1.2.3", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			test.assertVersionConstraint(t, PortageFormat, constraint)
		})
	}
}

func TestPortageConstraint_Satisfied_NilVersion(t *testing.T) {
	tests := []struct {
		name        string
		constraint  string
		expected    bool
		shouldError bool
	}{
		{
			name:        "empty constraint with nil version",
			constraint:  "",
			expected:    true,
			shouldError: false,
		},
		{
			name:        "non-empty constraint with nil version",
			constraint:  "> 1.0.0",
			expected:    false,
			shouldError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			satisfied, err := c.Satisfied(nil)
			if test.shouldError {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, satisfied)
			}
		})
	}
}

func TestPortageConstraint_Satisfied_UnsupportedFormat(t *testing.T) {
	c, err := GetConstraint("> 1.0.0", PortageFormat)
	assert.NoError(t, err)

	// Test with a semantic version (wrong format)
	version, err := NewVersion("1.2.3", SemanticFormat)
	assert.NoError(t, err)

	satisfied, err := c.Satisfied(version)
	require.Error(t, err)
	assert.False(t, satisfied)
	assert.Contains(t, err.Error(), "unsupported version comparison")
}

func TestPortageConstraint_String(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		expected   string
	}{
		{
			name:       "empty constraint",
			constraint: "",
			expected:   "none (portage)",
		},
		{
			name:       "simple constraint",
			constraint: "> 1.0.0",
			expected:   "> 1.0.0 (portage)",
		},
		{
			name:       "complex constraint",
			constraint: "> 1.0.0, < 2.0.0",
			expected:   "> 1.0.0, < 2.0.0 (portage)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			result := constraint.String()
			assert.Equal(t, test.expected, result)
		})
	}
}
