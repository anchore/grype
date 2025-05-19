package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebVersionCompare(t *testing.T) {
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
			thisVersion:  "1.2.3-1",
			otherVersion: "1.2.3-2",
			otherFormat:  DebFormat,
			expectError:  false,
		},
		{
			name:           "different format returns error",
			thisVersion:    "1.2.3-1",
			otherVersion:   "1.2.3",
			otherFormat:    SemanticFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - apk",
			thisVersion:    "1.2.3-1",
			otherVersion:   "1.2.3-r4",
			otherFormat:    ApkFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid deb format",
			thisVersion:  "1.2.3-1",
			otherVersion: "1.2.3-2",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid deb format",
			thisVersion:    "1.2.3-1",
			otherVersion:   "not-valid-deb-format",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newDebVersion(test.thisVersion)
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

func TestDebVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*debVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*debVersion, *Version) {
				thisVer, _ := newDebVersion("1.2.3-1")
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty debVersion in other object",
			setupFunc: func() (*debVersion, *Version) {
				thisVer, _ := newDebVersion("1.2.3-1")

				otherVer := &Version{
					Raw:    "1.2.3-2",
					Format: DebFormat,
					rich:   rich{}, // debVer will be nil
				}

				return thisVer, otherVer
			},
			expectError:    true,
			errorSubstring: "given empty debVersion object",
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
