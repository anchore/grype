package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApkVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		thisVersion    string
		otherVersion   string
		otherFormat    Format
		expectError    bool
		errorSubstring string
	}{
		{
			name:         "same format successful comparison",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  ApkFormat,
			expectError:  false,
		},
		{
			name:           "different format returns error",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "1.2.3",
			otherFormat:    SemanticFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - deb",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "1.2.3-1",
			otherFormat:    DebFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid apk format",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid apk format",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "not-valid-apk-format",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newApkVersion(test.thisVersion)
			require.NoError(t, err)

			otherVer, err := NewVersion(test.otherVersion, test.otherFormat)
			require.NoError(t, err)

			result, err := thisVer.Compare(otherVer)

			if test.expectError {
				assert.Error(t, err)
				if test.errorSubstring != "" {
					assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
						"Expected error to contain '%s', got: %v", test.errorSubstring, err)
				}
			} else {
				assert.NoError(t, err)
				assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
			}
		})
	}
}

func TestApkVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*apkVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*apkVersion, *Version) {
				thisVer, _ := newApkVersion("1.2.3-r4")
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty apkVersion in other object",
			setupFunc: func() (*apkVersion, *Version) {
				thisVer, _ := newApkVersion("1.2.3-r4")
				otherVer := &Version{
					Raw:    "1.2.3-r5",
					Format: ApkFormat,
					rich:   rich{}, // don't populate the rich.apkVer field
				}

				return thisVer, otherVer
			},
			expectError:    true,
			errorSubstring: "given empty apkVersion object",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc()

			_, err := thisVer.Compare(otherVer)

			assert.Error(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
