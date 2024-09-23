package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionJVM(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		// pre jep223 versions
		{"1.8", "1.8.0", 0},
		{"1.8.0", "1.8.0_0", 0},
		{"1.8.0", "1.8.0", 0},
		{"1.7.0", "1.8.0", -1},
		{"1.8.0_131", "1.8.0_131", 0},
		{"1.8.0_131", "1.8.0_132", -1},

		// builds should not matter
		{"1.8.0_131", "1.8.0_130", 1},
		{"1.8.0_131", "1.8.0_132-b11", -1},
		{"1.8.0_131-b11", "1.8.0_132-b11", -1},
		{"1.8.0_131-b11", "1.8.0_131-b12", 0},
		{"1.8.0_131-b11", "1.8.0_131-b10", 0},
		{"1.8.0_131-b11", "1.8.0_131", 0},
		{"1.8.0_131-b11", "1.8.0_131-b11", 0},

		// jep223 versions (semver)
		{"8.0.4", "8.0.4", 0},
		{"8.0.4", "8.0.5", -1},
		{"8.0.4", "8.0.3", 1},
		{"8.0.4", "8.0.4+b1", 0},

		// mix comparison
		{"1.8.0_131", "8.0.4", 1},           // 1.8.0_131 --> 8.0.131
		{"8.0.4", "1.8.0_131", -1},          // doesn't matter which side the comparison is on
		{"1.8.0_131-b002", "8.0.131+b2", 0}, // builds should not matter
		{"1.8.0_131-b002", "8.0.131+b1", 0}, // builds should not matter
		{"1.6.0", "8.0.1", -1},              // 1.6.0 --> 6.0.0

		// prerelease
		{"1.8.0_13-ea-b002", "1.8.0_13-ea-b001", 0},
		{"1.8.0_13-ea", "1.8.0_13-ea-b001", 0},
		{"1.8.0_13-ea-b002", "8.0.13-ea+b2", 0},
		{"1.8.0_13-ea-b002", "8.0.13+b2", -1},
		{"1.8.0_13-b002", "8.0.13-ea+b2", 1},

		// pre 1.8 (when the jep 223 was introduced)
		{"1.7.0", "7.0.0", 0}, // there is no v7 of the JVM, but we want to honor this comparison since it may be someone mistakenly using the wrong version format

		// invalid but we should work with these
		{"1.8.0_131", "1.8.0-update131-b02", 0},
		{"1.8.0_131", "1.8.0-update_131-b02", 0},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1, err := newJvmVersion(test.v1)
			require.NotNil(t, v1)
			require.NoError(t, err)

			v2, err := newJvmVersion(test.v2)
			require.NotNil(t, v2)
			require.NoError(t, err)

			actual := v1.compare(*v2)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestConvertNonCompliantSemver(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple update",
			input:    "8.0-update302",
			expected: "8.0.302",
		},
		{
			name:     "update with build",
			input:    "8.0-update302-b08",
			expected: "8.0.302+8",
		},
		{
			name:     "update with underscore and build",
			input:    "8.0-update_302-b08",
			expected: "8.0.302+8",
		},
		{
			name:     "version without patch and prerelease",
			input:    "8.0.0",
			expected: "8.0.0",
		},
		{
			name:     "version with patch, no update",
			input:    "8.0.100",
			expected: "8.0.100",
		},
		{
			name:     "version with patch and prerelease",
			input:    "8.0.0-rc1",
			expected: "8.0.0-rc1",
		},
		{
			name:     "invalid update format, no update keyword",
			input:    "8.0-foo302",
			expected: "8.0-foo302",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertNonCompliantSemver(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVersionJVM_invalid(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantErr require.ErrorAssertionFunc
	}{
		{
			name:    "invalid version",
			version: "1.a",
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}
			v, err := newJvmVersion(tt.version)
			assert.Nil(t, v)
			tt.wantErr(t, err)
		})
	}
}
