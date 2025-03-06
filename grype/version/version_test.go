package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		version1       string
		version2       string
		format         Format
		expectedResult int
		expectErr      bool
	}{
		{
			name:           "v1 greater than v2",
			version1:       "2.0.0",
			version2:       "1.0.0",
			format:         SemanticFormat,
			expectedResult: 1,
			expectErr:      false,
		},
		{
			name:           "v1 less than v2",
			version1:       "1.0.0",
			version2:       "2.0.0",
			format:         SemanticFormat,
			expectedResult: -1,
			expectErr:      false,
		},
		{
			name:           "v1 equal to v2",
			version1:       "1.0.0",
			version2:       "1.0.0",
			format:         SemanticFormat,
			expectedResult: 0,
			expectErr:      false,
		},
		{
			name:           "compare with nil version",
			version1:       "1.0.0",
			version2:       "",
			format:         SemanticFormat,
			expectedResult: -1,
			expectErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v1, err := NewVersion(tc.version1, tc.format)
			require.NoError(t, err, "failed to create version1")

			var v2 *Version
			if tc.version2 == "" {
				v2 = nil // test nil case
			} else if tc.name == "different formats" {
				// use a different format for the second version
				v2, err = NewVersion(tc.version2, PythonFormat)
				require.NoError(t, err, "failed to create version2 with different format")
			} else {
				v2, err = NewVersion(tc.version2, tc.format)
				require.NoError(t, err, "failed to create version2")
			}

			result, err := v1.Compare(v2)

			if tc.expectErr {
				assert.Error(t, err, "expected an error but got none")
			} else {
				assert.NoError(t, err, "unexpected error during comparison")
				assert.Equal(t, tc.expectedResult, result, "comparison result mismatch")
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
