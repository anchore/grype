package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hashiVer "github.com/anchore/go-version"
)

func TestGolangVersion_Constraint(t *testing.T) {
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

func TestGolangVersion_String(t *testing.T) {
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
			c, err := GetConstraint(tc.constraint, GolangFormat)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, c.String())
		})
	}
}

func TestGolangVersion_Compare(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		expected int
	}{
		{
			name:     "same basic version",
			version1: "v1.2.3",
			version2: "v1.2.3",
			expected: 0,
		},
		{
			name:     "same version with incompatible",
			version1: "v3.2.0+incompatible",
			version2: "v3.2.0+incompatible",
			expected: 0,
		},
		{
			name:     "same go stdlib version",
			version1: "go1.24.1",
			version2: "go1.24.1",
			expected: 0,
		},
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
		{
			name:     "semver this version less",
			version1: "v1.2.3",
			version2: "v1.2.4",
			expected: -1,
		},
		{
			name:     "semver this version more",
			version1: "v1.3.4",
			version2: "v1.2.4",
			expected: 1,
		},
		{
			name:     "semver equal",
			version1: "v1.2.4",
			version2: "v1.2.4",
			expected: 0,
		},
		{
			name:     "commit-sha this version less",
			version1: "v0.0.0-20180116102854-5a71ef0e047d",
			version2: "v0.0.0-20190116102854-somehash",
			expected: -1,
		},
		{
			name:     "commit-sha this version more",
			version1: "v0.0.0-20180216102854-5a71ef0e047d",
			version2: "v0.0.0-20180116102854-somehash",
			expected: 1,
		},
		{
			name:     "commit-sha this version equal",
			version1: "v0.0.0-20180116102854-5a71ef0e047d",
			version2: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: 0,
		},
		{
			name:     "this pre-semver is less than any semver",
			version1: "v0.0.0-20180116102854-5a71ef0e047d",
			version2: "v0.0.1",
			expected: -1,
		},
		{
			name:     "semver is greater than timestamp",
			version1: "v2.1.0",
			version2: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: 1,
		},
		{
			name:     "pseudoversion less than other pseudoversion",
			version1: "v0.0.0-20170116102854-1ef0e047d5a7",
			version2: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: -1,
		},
		{
			name:     "pseudoversion greater than other pseudoversion",
			version1: "v0.0.0-20190116102854-8a3f0e047d5a",
			version2: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: 1,
		},
		{
			name:     "+incompatible doesn't break equality",
			version1: "v3.2.0",
			version2: "v3.2.0+incompatible",
			expected: 0,
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

func TestGolangVersion_Compare_NilVersion(t *testing.T) {
	version, err := NewVersion("v1.2.3", GolangFormat)
	require.NoError(t, err)

	result, err := version.Compare(nil)
	require.Error(t, err)
	assert.Equal(t, ErrNoVersionProvided, err)
	assert.Equal(t, -1, result)
}

func TestGolangVersion_Compare_DifferentFormat(t *testing.T) {
	golangVer, err := newGolangVersion("v1.2.3")
	require.NoError(t, err)

	semanticVer, err := NewVersion("1.2.3", SemanticFormat)
	require.NoError(t, err)

	result, err := golangVer.Compare(semanticVer)
	require.NoError(t, err)
	assert.Equal(t, 0, result)
}

func TestGolangVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected golangVersion
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:  "normal semantic version",
			input: "v1.8.0",
			expected: golangVersion{
				raw: "v1.8.0",
				obj: hashiVer.Must(hashiVer.NewSemver("v1.8.0")),
			},
		},
		{
			name:  "v0.0.0 date and hash version",
			input: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: golangVersion{
				raw: "v0.0.0-20180116102854-5a71ef0e047d",
				obj: hashiVer.Must(hashiVer.NewSemver("v0.0.0-20180116102854-5a71ef0e047d")),
			},
		},
		{
			name:  "semver with +incompatible",
			input: "v24.0.7+incompatible",
			expected: golangVersion{
				raw: "v24.0.7+incompatible",
				obj: hashiVer.Must(hashiVer.NewSemver("v24.0.7+incompatible")),
			},
		},
		{
			name:  "semver with +incompatible+dirty",
			input: "v24.0.7+incompatible+dirty",
			expected: golangVersion{
				raw: "v24.0.7+incompatible+dirty",
				obj: hashiVer.Must(hashiVer.NewSemver("v24.0.7+incompatible.dirty")),
			},
		},
		{
			name:  "standard library",
			input: "go1.21.4",
			expected: golangVersion{
				raw: "go1.21.4",
				obj: hashiVer.Must(hashiVer.NewSemver("1.21.4")),
			},
		},
		{
			// "(devel)" is the main module of a go program.
			// If we get a package with this version, it means the SBOM
			// doesn't have a real version number for the built package, so
			// we can't compare it and should just return an error.
			name:  "devel",
			input: "(devel)",
			wantErr: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				require.ErrorIs(t, err, ErrUnsupportedVersion)
			},
		},
		{
			name:    "invalid",
			input:   "invalid",
			wantErr: require.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr == nil {
				tc.wantErr = require.NoError
			}
			v, err := newGolangVersion(tc.input)
			tc.wantErr(t, err)
			if err != nil {
				return
			}
			assert.Equal(t, tc.expected, v)
		})
	}
}
