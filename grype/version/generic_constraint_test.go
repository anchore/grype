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
		formatName string
		expected   string
	}{
		{
			name:       "empty constraint",
			constraint: "",
			formatName: "test",
			expected:   "none (test)",
		},
		{
			name:       "simple constraint",
			constraint: "> 1.0.0",
			formatName: "semantic",
			expected:   "> 1.0.0 (semantic)",
		},
		{
			name:       "complex constraint",
			constraint: ">= 1.0.0, < 2.0.0",
			formatName: "maven",
			expected:   ">= 1.0.0, < 2.0.0 (maven)",
		},
		{
			name:       "jvm format name",
			constraint: "< 11",
			formatName: "jvm",
			expected:   "< 11 (jvm)",
		},
		{
			name:       "go format name",
			constraint: "> v1.2.3",
			formatName: "go",
			expected:   "> v1.2.3 (go)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create a mock comparator generator that always succeeds
			mockGenerator := func(unit constraintUnit) (Comparator, error) {
				ver, err := NewVersion(unit.rawVersion, SemanticFormat)
				if err != nil {
					return nil, err
				}
				return ver.comparator, nil
			}

			constraint, err := newGenericConstraint(test.constraint, mockGenerator, test.formatName)
			require.NoError(t, err)

			result := constraint.String()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestGenericConstraint_Satisfied_EmptyConstraint(t *testing.T) {
	// Create a mock comparator generator
	mockGenerator := func(unit constraintUnit) (Comparator, error) {
		ver, err := NewVersion(unit.rawVersion, SemanticFormat)
		if err != nil {
			return nil, err
		}
		return ver.comparator, nil
	}

	constraint, err := newGenericConstraint("", mockGenerator, "test")
	require.NoError(t, err)

	tests := []struct {
		name    string
		version *Version
	}{
		{
			name:    "with valid version",
			version: mustNewVersion(t, "1.2.3", SemanticFormat),
		},
		{
			name:    "with nil version",
			version: nil,
		},
		{
			name:    "with different format version",
			version: mustNewVersion(t, "1.2.3-r1", ApkFormat),
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
	// Create a comparator generator that uses semantic versioning
	semanticGenerator := func(unit constraintUnit) (Comparator, error) {
		ver, err := NewVersion(unit.rawVersion, SemanticFormat)
		if err != nil {
			return nil, err
		}
		return ver.comparator, nil
	}

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
			constraint, err := newGenericConstraint(test.constraint, semanticGenerator, "test")
			require.NoError(t, err)

			version := mustNewVersion(t, test.version, SemanticFormat)

			satisfied, err := constraint.Satisfied(version)
			if test.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.satisfied, satisfied)
			}
		})
	}
}

func TestGenericConstraint_InvalidConstraint(t *testing.T) {
	// Create a comparator generator that might fail
	mockGenerator := func(unit constraintUnit) (Comparator, error) {
		ver, err := NewVersion(unit.rawVersion, SemanticFormat)
		if err != nil {
			return nil, err
		}
		return ver.comparator, nil
	}

	tests := []struct {
		name       string
		constraint string
	}{
		{
			name:       "invalid operator",
			constraint: "~~ 1.0.0",
		},
		{
			name:       "invalid version",
			constraint: "> not.a.version",
		},
		{
			name:       "malformed constraint",
			constraint: "> 1.0.0 < 2.0.0", // missing comma
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := newGenericConstraint(test.constraint, mockGenerator, "test")
			assert.Error(t, err)
		})
	}
}

func TestGenericConstraint_CompilerGeneratorError(t *testing.T) {
	// Create a comparator generator that always fails
	failingGenerator := func(unit constraintUnit) (Comparator, error) {
		return nil, assert.AnError
	}

	_, err := newGenericConstraint("> 1.0.0", failingGenerator, "test")
	assert.Error(t, err)
}

func TestGenericConstraint_ActualUsage_JVM(t *testing.T) {
	// Test actual usage patterns similar to JVM constraints
	constraint, err := newGenericConstraint(">= 8", newJvmComparator, "jvm")
	require.NoError(t, err)

	// Test with a JVM version
	version, err := NewVersion("11", JVMFormat)
	require.NoError(t, err)

	satisfied, err := constraint.Satisfied(version)
	assert.NoError(t, err)
	assert.True(t, satisfied)

	// Test string representation
	assert.Equal(t, ">= 8 (jvm)", constraint.String())
}

func TestGenericConstraint_ActualUsage_Golang(t *testing.T) {
	// Test actual usage patterns similar to Golang constraints
	constraint, err := newGenericConstraint("< v1.20.0", newGolangComparator, "go")
	require.NoError(t, err)

	// Test with a Golang version
	version, err := NewVersion("v1.19.5", GolangFormat)
	require.NoError(t, err)

	satisfied, err := constraint.Satisfied(version)
	assert.NoError(t, err)
	assert.True(t, satisfied)

	// Test string representation
	assert.Equal(t, "< v1.20.0 (go)", constraint.String())
}

// Helper function to create versions for testing
func mustNewVersion(t *testing.T, version string, format Format) *Version {
	t.Helper()
	v, err := NewVersion(version, format)
	require.NoError(t, err)
	return v
}
