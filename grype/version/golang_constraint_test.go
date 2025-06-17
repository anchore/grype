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
			c, err := GetConstraint(tc.constraint, GolangFormat)
			require.NoError(t, err)
			v, err := NewVersion(tc.version, GolangFormat)
			require.NoError(t, err)
			sat, err := c.Satisfied(v)
			require.NoError(t, err)
			assert.Equal(t, tc.satisfied, sat)
		})
	}
}

func TestGolangVersionCompare_NilVersion(t *testing.T) {
	version, err := NewVersion("v1.2.3", GolangFormat)
	require.NoError(t, err)

	result, err := version.Compare(nil)
	require.Error(t, err)
	assert.Equal(t, ErrNoVersionProvided, err)
	assert.Equal(t, -1, result)
}

func TestGolangVersionCompare_DifferentFormat(t *testing.T) {
	golangVer, err := newGolangVersion("v1.2.3")
	require.NoError(t, err)

	semanticVer, err := NewVersion("1.2.3", SemanticFormat)
	require.NoError(t, err)

	result, err := golangVer.Compare(semanticVer)
	require.NoError(t, err)
	assert.Equal(t, 0, result)
}

func TestGolangVersionCompare_SameRawVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "same basic version",
			version: "v1.2.3",
		},
		{
			name:    "same version with incompatible",
			version: "v3.2.0+incompatible",
		},
		{
			name:    "same go stdlib version",
			version: "go1.24.1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version1, err := NewVersion(test.version, GolangFormat)
			require.NoError(t, err)

			version2, err := NewVersion(test.version, GolangFormat)
			require.NoError(t, err)

			result, err := version1.Compare(version2)
			assert.NoError(t, err)
			assert.Equal(t, 0, result)
		})
	}
}

//func TestGolangVersionCompare_DevelVersion(t *testing.T) {
//	version, err := NewVersion("v1.2.3", GolangFormat)
//	require.NoError(t, err)
//
//	// create a version object with "(devel)" as the raw value
//	// we need to manually create this since NewVersion would reject "(devel)"
//	develVersion := &Version{
//		Raw:    "(devel)",
//		Format: GolangFormat,
//		comparator: golangVersion{
//			raw: "(devel)",
//			obj: nil,
//		},
//	}
//
//	result, err := version.Compare(develVersion)
//	require.Error(t, err)
//	assert.Contains(t, err.Error(), "cannot compare a non-development version")
//	assert.Contains(t, err.Error(), "with a default development version")
//	assert.Equal(t, -1, result)
//}

func TestGolangVersionCompare_NormalComparison(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		expected int
	}{
		{
			name:     "version1 less than version2",
			version1: "v1.2.3",
			version2: "v1.2.4",
			expected: -1,
		},
		{
			name:     "version1 greater than version2",
			version1: "v1.2.4",
			version2: "v1.2.3",
			expected: 1,
		},
		{
			name:     "version1 equal to version2",
			version1: "v1.2.3",
			version2: "v1.2.3",
			expected: 0,
		},
		{
			name:     "go stdlib versions",
			version1: "go1.23.1",
			version2: "go1.24.1",
			expected: -1,
		},
		{
			name:     "incompatible versions",
			version1: "v3.1.0+incompatible",
			version2: "v3.2.0+incompatible",
			expected: -1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version1, err := NewVersion(test.version1, GolangFormat)
			require.NoError(t, err)

			version2, err := NewVersion(test.version2, GolangFormat)
			require.NoError(t, err)

			result, err := version1.Compare(version2)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
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
