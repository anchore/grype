package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitnamiVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		thisVersion    string
		otherVersion   string
		otherFormat    Format
		expectError    bool
		errorSubstring string
	}{
		{
			name:         "different format returns error",
			thisVersion:  "1.2.3-4",
			otherVersion: "1.2.3",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:           "same format successful comparison",
			thisVersion:    "1.2.3-4",
			otherVersion:   "1.2.3-5",
			otherFormat:    BitnamiFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - deb",
			thisVersion:    "1.2.3-4",
			otherVersion:   "1.2.3-1",
			otherFormat:    DebFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid semver format",
			thisVersion:  "1.2.3-4",
			otherVersion: "1.2.3-5",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid semver format",
			thisVersion:    "1.2.3-4",
			otherVersion:   "not-valid-semver-format",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newBitnamiVersion(test.thisVersion)
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

func TestBitnamiVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*semanticVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*semanticVersion, *Version) {
				thisVer, _ := newBitnamiVersion("1.2.3-4")
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty semanticVersion in other object",
			setupFunc: func() (*semanticVersion, *Version) {
				thisVer, _ := newBitnamiVersion("1.2.3-4")
				otherVer := &Version{
					Raw:    "1.2.3-5",
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
