package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKbVersionCompare(t *testing.T) {
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
			thisVersion:  "KB4562562",
			otherVersion: "KB4562563",
			otherFormat:  KBFormat,
			expectError:  false,
		},
		{
			name:           "different format returns error",
			thisVersion:    "KB4562562",
			otherVersion:   "1.2.3",
			otherFormat:    SemanticFormat,
			expectError:    true,
			errorSubstring: `(KB) unsupported version comparison: value="1.2.3" format="Semantic"`,
		},
		{
			name:         "unknown format attempts upgrade - valid kb format",
			thisVersion:  "KB4562562",
			otherVersion: "KB4562563",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := NewVersion(test.thisVersion, KBFormat)
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

func TestKbVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				v, err := NewVersion("KB4562562", KBFormat)
				require.NoError(t, err)
				return v, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty kbVersion in other object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := newKBVersion("KB4562562")

				otherVer := &Version{
					Raw:    "KB4562563",
					Format: KBFormat,
				}

				return &Version{
					Raw:        "KB4562562",
					Format:     KBFormat,
					comparator: thisVer,
				}, otherVer
			},
			expectError:    true,
			errorSubstring: `cannot compare "KB" formatted version with empty version object`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc(t)

			_, err := thisVer.Compare(otherVer)

			assert.Error(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
