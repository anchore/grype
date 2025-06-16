package version

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		v1             string
		v2             string
		expectedResult int
		expectErr      require.ErrorAssertionFunc
	}{
		{
			name:           "v1 greater than v2",
			v1:             "2.0.0",
			v2:             "1.0.0",
			expectedResult: 1,
		},
		{
			name:           "v1 less than v2",
			v1:             "1.0.0",
			v2:             "2.0.0",
			expectedResult: -1,
		},
		{
			name:           "v1 equal to v2",
			v1:             "1.0.0",
			v2:             "1.0.0",
			expectedResult: 0,
		},
		{
			name:           "compare with nil version",
			v1:             "1.0.0",
			v2:             "",
			expectedResult: -1,
			expectErr:      require.Error,
		},
	}

	// the above test cases are pretty tame value-wise, so we can use (almost) all formats
	var formats []Format
	formats = append(formats, Formats...)

	// leave out some formats...
	slices.DeleteFunc(formats, func(f Format) bool {
		return f == KBFormat
	})

	for _, format := range formats {
		t.Run(format.String(), func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					if tc.expectErr == nil {
						tc.expectErr = require.NoError
					}
					v1, err := NewVersion(tc.v1, format)
					require.NoError(t, err, "failed to create version1")
					require.Equal(t, format, v1.Format)

					var v2 *Version
					if tc.v2 != "" {
						v2, err = NewVersion(tc.v2, format)
						require.NoError(t, err, "failed to create version2")
						require.Equal(t, format, v2.Format)
					}

					result, err := v1.Compare(v2)
					tc.expectErr(t, err, "unexpected error during comparison")
					if err != nil {
						return // skip further checks if there was an error
					}

					assert.NoError(t, err, "unexpected error during comparison")
					assert.Equal(t, tc.expectedResult, result, "comparison result mismatch")
				})
			}
		})
	}
}

func Test_UpgradeUnknownRightSideComparison(t *testing.T) {
	v1, err := NewVersion("1.0.0", SemanticFormat)
	require.NoError(t, err)

	// test if we can upgrade an unknown format to a known format when the left hand side is known
	v2, err := NewVersion("1.0.0", UnknownFormat)
	require.NoError(t, err)

	result, err := v1.Compare(v2)
	assert.NoError(t, err)
	assert.Equal(t, 0, result, "versions should be equal after format conversion")
}

func TestVersionCompareSameFormat(t *testing.T) {
	formats := []struct {
		name   string
		format Format
	}{
		{"Semantic", SemanticFormat},
		{"APK", ApkFormat},
		{"Deb", DebFormat},
		{"Golang", GolangFormat},
		{"Maven", MavenFormat},
		{"RPM", RpmFormat},
		{"Python", PythonFormat},
		{"KB", KBFormat},
		{"Gem", GemFormat},
		{"Portage", PortageFormat},
		{"JVM", JVMFormat},
		{"Unknown", UnknownFormat},
	}

	for _, fmt := range formats {
		t.Run(fmt.name, func(t *testing.T) {
			// just test that we can create and compare versions of this format
			// without errors - not testing the actual comparison logic
			v1, err := NewVersion("1.0.0", fmt.format)
			if err != nil {
				t.Skipf("Skipping %s format, couldn't create version: %v", fmt.name, err)
			}

			v2, err := NewVersion("1.0.0", fmt.format)
			if err != nil {
				t.Skipf("Skipping %s format, couldn't create second version: %v", fmt.name, err)
			}

			result, err := v1.Compare(v2)
			assert.NoError(t, err, "comparison error")
			assert.Equal(t, 0, result, "equal versions should return 0")
		})
	}
}
