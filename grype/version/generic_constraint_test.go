package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenericConstraint_String(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		format     Format
		expected   string
	}{
		{
			name:       "empty constraint",
			constraint: "",
			format:     SemanticFormat,
			expected:   "none (semantic)",
		},
		{
			name:       "simple constraint",
			constraint: "> 1.0.0",
			format:     SemanticFormat,
			expected:   "> 1.0.0 (semantic)",
		},
		{
			name:       "complex constraint",
			constraint: ">= 1.0.0, < 2.0.0",
			format:     MavenFormat,
			expected:   ">= 1.0.0, < 2.0.0 (maven)",
		},
		{
			name:       "jvm format name",
			constraint: "< 11",
			format:     JVMFormat,
			expected:   "< 11 (jvm)",
		},
		{
			name:       "go format name",
			constraint: "> v1.2.3",
			format:     GolangFormat,
			expected:   "> v1.2.3 (go)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(test.format, test.constraint)
			require.NoError(t, err)

			result := constraint.String()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGenericConstraint_Satisfied_EmptyConstraint(t *testing.T) {
	constraint, err := newGenericConstraint(SemanticFormat, "")
	require.NoError(t, err)

	tests := []struct {
		name    string
		version *Version
	}{
		{
			name:    "with valid version",
			version: NewVersion("1.2.3", SemanticFormat),
		},
		{
			name:    "with nil version",
			version: nil,
		},
		{
			name:    "with different format version",
			version: NewVersion("1.2.3-r1", ApkFormat),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			satisfied, err := constraint.Satisfied(test.version)
			assert.NoError(t, err)
			assert.True(t, satisfied, "empty constraint should always be satisfied")
		})
	}
}

func TestGenericConstraint_Satisfied_WithConstraint(t *testing.T) {
	tests := []struct {
		name        string
		constraint  string
		version     string
		satisfied   bool
		shouldError bool
	}{
		{
			name:       "simple greater than - satisfied",
			constraint: "> 1.0.0",
			version:    "1.2.3",
			satisfied:  true,
		},
		{
			name:       "simple greater than - not satisfied",
			constraint: "> 2.0.0",
			version:    "1.2.3",
			satisfied:  false,
		},
		{
			name:       "complex constraint - satisfied",
			constraint: ">= 1.0.0, < 2.0.0",
			version:    "1.5.0",
			satisfied:  true,
		},
		{
			name:       "complex constraint - not satisfied",
			constraint: ">= 1.0.0, < 2.0.0",
			version:    "2.5.0",
			satisfied:  false,
		},
		{
			name:       "equality constraint - satisfied",
			constraint: "= 1.2.3",
			version:    "1.2.3",
			satisfied:  true,
		},
		{
			name:       "equality constraint - not satisfied",
			constraint: "= 1.2.3",
			version:    "1.2.4",
			satisfied:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(SemanticFormat, test.constraint)
			require.NoError(t, err)

			version := NewVersion(test.version, SemanticFormat)

			satisfied, err := constraint.Satisfied(version)
			if test.shouldError {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.satisfied, satisfied)
			}
		})
	}
}

func TestGenericConstraint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		gen        func(unit rangeUnit) (Comparator, error)
	}{
		{
			name:       "invalid Operator",
			constraint: "~~ 1.0.0",
		},
		{
			name:       "malformed constraint",
			constraint: "> 1.0.0 < 2.0.0", // missing comma
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newGenericConstraint(SemanticFormat, test.constraint)
			require.Error(t, err)
		})
	}
}
