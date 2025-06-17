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
			errorSubstring: "invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newSemanticVersion(test.thisVersion, true)
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
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer, err := NewVersion("1.2.3", SemanticFormat)
				require.NoError(t, err)
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc(t)

			_, err := thisVer.Compare(otherVer)

			require.Error(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
