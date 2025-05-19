package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFuzzyVersionCompare(t *testing.T) {
	tests := []struct {
		name           string
		thisVersion    string
		otherVersion   string
		otherFormat    Format
		expectError    bool
		errorSubstring string
	}{
		{
			name:         "fuzzy comparison with semantic version",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "fuzzy comparison with unknown format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:         "fuzzy comparison with different format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.3-r4",
			otherFormat:  ApkFormat,
			expectError:  false,
		},
		{
			name:         "fuzzy comparison with non-semantic string",
			thisVersion:  "1.2.3",
			otherVersion: "abc123",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:         "fuzzy comparison with empty strings",
			thisVersion:  "1.2.3",
			otherVersion: "",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer := fuzzyVersion{
				raw: test.thisVersion,
			}

			// if thisVersion is semantic-compatible, populate the semVer field
			if semver, err := newSemanticVersion(test.thisVersion); err == nil {
				thisVer.semVer = semver
			}

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

func TestFuzzyVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*fuzzyVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*fuzzyVersion, *Version) {
				thisVer := &fuzzyVersion{
					raw: "1.2.3",
				}
				if semver, err := newSemanticVersion("1.2.3"); err == nil {
					thisVer.semVer = semver
				}
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "semantic format but empty semver object",
			setupFunc: func() (*fuzzyVersion, *Version) {
				thisVer := &fuzzyVersion{
					raw: "1.2.3",
				}
				if semver, err := newSemanticVersion("1.2.3"); err == nil {
					thisVer.semVer = semver
				}

				otherVer := &Version{
					Raw:    "1.2.4",
					Format: SemanticFormat,
					rich:   rich{}, // semVer will be nil
				}

				return thisVer, otherVer
			},
			expectError:    true,
			errorSubstring: "given empty semver object (fuzzy)",
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
