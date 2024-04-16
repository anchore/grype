package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hashiVer "github.com/anchore/go-version"
)

func TestNewGolangVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected golangVersion
		wantErr  bool
	}{
		{
			name:  "normal semantic version",
			input: "v1.8.0",
			expected: golangVersion{
				raw:    "v1.8.0",
				semVer: hashiVer.Must(hashiVer.NewSemver("v1.8.0")),
			},
		},
		{
			name:  "v0.0.0 date and hash version",
			input: "v0.0.0-20180116102854-5a71ef0e047d",
			expected: golangVersion{
				raw:    "v0.0.0-20180116102854-5a71ef0e047d",
				semVer: hashiVer.Must(hashiVer.NewSemver("v0.0.0-20180116102854-5a71ef0e047d")),
			},
		},
		{
			name:  "semver with +incompatible",
			input: "v24.0.7+incompatible",
			expected: golangVersion{
				raw:    "v24.0.7+incompatible",
				semVer: hashiVer.Must(hashiVer.NewSemver("v24.0.7+incompatible")),
			},
		},
		{
			name:  "standard library",
			input: "go1.21.4",
			expected: golangVersion{
				raw:    "go1.21.4",
				semVer: hashiVer.Must(hashiVer.NewSemver("1.21.4")),
			},
		},
		{
			// "(devel)" is the main module of a go program.
			// If we get a package with this version, it means the SBOM
			// doesn't have a real version number for the built package, so
			// we can't compare it and should just return an error.
			name:    "devel",
			input:   "(devel)",
			wantErr: true,
		},
		{
			name:    "invalid input",
			input:   "some nonsense",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newGolangVersion(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			assert.Equal(t, tc.expected, *v)
		})
	}
}

func TestCompareGolangVersions(t *testing.T) {
	tests := []struct {
		name         string
		thisVersion  string
		otherVersion string
		want         int
	}{
		{
			name:         "semver this version less",
			thisVersion:  "v1.2.3",
			otherVersion: "v1.2.4",
			want:         -1,
		},
		{
			name:         "semver this version more",
			thisVersion:  "v1.3.4",
			otherVersion: "v1.2.4",
			want:         1,
		},
		{
			name:         "semver equal",
			thisVersion:  "v1.2.4",
			otherVersion: "v1.2.4",
			want:         0,
		},
		{
			name:         "commit-sha this version less",
			thisVersion:  "v0.0.0-20180116102854-5a71ef0e047d",
			otherVersion: "v0.0.0-20190116102854-somehash",
			want:         -1,
		},
		{
			name:         "commit-sha this version more",
			thisVersion:  "v0.0.0-20180216102854-5a71ef0e047d",
			otherVersion: "v0.0.0-20180116102854-somehash",
			want:         1,
		},
		{
			name:         "commit-sha this version equal",
			thisVersion:  "v0.0.0-20180116102854-5a71ef0e047d",
			otherVersion: "v0.0.0-20180116102854-5a71ef0e047d",
			want:         0,
		},
		{
			name:         "this pre-semver is less than any semver",
			thisVersion:  "v0.0.0-20180116102854-5a71ef0e047d",
			otherVersion: "v0.0.1",
			want:         -1,
		},
		{
			name:         "semver is greater than timestamp",
			thisVersion:  "v2.1.0",
			otherVersion: "v0.0.0-20180116102854-5a71ef0e047d",
			want:         1,
		},
		{
			name:         "pseudoversion less than other pseudoversion",
			thisVersion:  "v0.0.0-20170116102854-1ef0e047d5a7",
			otherVersion: "v0.0.0-20180116102854-5a71ef0e047d",
			want:         -1,
		},
		{
			name:         "pseudoversion greater than other pseudoversion",
			thisVersion:  "v0.0.0-20190116102854-8a3f0e047d5a",
			otherVersion: "v0.0.0-20180116102854-5a71ef0e047d",
			want:         1,
		},
		{
			name:         "+incompatible doesn't break equality",
			thisVersion:  "v3.2.0",
			otherVersion: "v3.2.0+incompatible",
			want:         0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := newGolangVersion(tc.thisVersion)
			require.NoError(t, err)
			other, err := newGolangVersion(tc.otherVersion)
			require.NoError(t, err)
			got := a.compare(*other)
			assert.Equal(t, tc.want, got)
		})
	}
}

func Test_newGolangVersion_UnsupportedVersion(t *testing.T) {
	tests := []struct {
		name    string
		v       string
		want    *golangVersion
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "devel",
			v:    "(devel)",
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				return assert.ErrorIs(t, err, ErrUnsupportedVersion)
			},
		},
		{
			name:    "invalid",
			v:       "invalid",
			wantErr: assert.Error,
		},
		{
			name: "valid",
			v:    "v1.2.3",
			want: &golangVersion{
				raw:    "v1.2.3",
				semVer: hashiVer.Must(hashiVer.NewSemver("v1.2.3")),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newGolangVersion(tt.v)
			if tt.wantErr != nil {
				tt.wantErr(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
