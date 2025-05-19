package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemanticVersionCompare_Format(t *testing.T) {
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
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with prerelease",
			thisVersion:  "1.2.3-alpha",
			otherVersion: "1.2.3-beta",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with build metadata",
			thisVersion:  "1.2.3+build.1",
			otherVersion: "1.2.3+build.2",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:           "different format returns error",
			thisVersion:    "1.2.3",
			otherVersion:   "1.2.3-1",
			otherFormat:    DebFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - apk",
			thisVersion:    "1.2.3",
			otherVersion:   "1.2.3-r4",
			otherFormat:    ApkFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - rpm",
			thisVersion:    "1.2.3",
			otherVersion:   "1.2.3-1",
			otherFormat:    RpmFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid semantic format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid semantic format",
			thisVersion:    "1.2.3",
			otherVersion:   "not.valid.semver",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newSemanticVersion(test.thisVersion)
			require.NoError(t, err)

			otherVer, err := NewVersion(test.otherVersion, test.otherFormat)
			require.NoError(t, err)

			result, err := thisVer.Compare(otherVer)

			if test.expectError {
				require.Error(t, err)
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

func TestSemanticVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*semanticVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*semanticVersion, *Version) {
				thisVer, _ := newSemanticVersion("1.2.3")
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty semanticVersion in other object",
			setupFunc: func() (*semanticVersion, *Version) {
				thisVer, _ := newSemanticVersion("1.2.3")

				otherVer := &Version{
					Raw:    "1.2.4",
					Format: SemanticFormat,
					rich:   rich{},
				}

				return thisVer, otherVer
			},
			expectError:    true,
			errorSubstring: "given empty semanticVersion object",
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
