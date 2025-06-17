package version

import (
	"strings"
	"testing"

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
			errorSubstring: "upstream_version must start with digit",
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
				require.Error(t, err)
				if test.errorSubstring != "" {
					require.True(t, strings.Contains(err.Error(), test.errorSubstring),
						"Expected error to contain '%s', got: %v", test.errorSubstring, err)
				}
			} else {
				require.NoError(t, err)
				require.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
			}
		})
	}
}

func TestDebVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer, err := NewVersion("1.2.3-1", DebFormat)
				require.NoError(t, err)
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty debVersion in other object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer, err := NewVersion("1.2.3-1", DebFormat)
				require.NoError(t, err)
				otherVer := &Version{
					Raw:    "1.2.3-2",
					Format: DebFormat,
				}

				return thisVer, otherVer
			},
			expectError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc(t)

			_, err := thisVer.Compare(otherVer)

			if test.expectError {
				require.Error(t, err)
			}
			if test.errorSubstring != "" {
				require.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
