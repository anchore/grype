package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFuzzyVersion_Compare(t *testing.T) {
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
			thisVer, err := NewVersion(test.thisVersion, UnknownFormat) // explicitly use the fuzzy version format
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

func TestFuzzyVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(tb testing.TB) (*Version, *Version)
		expectError    require.ErrorAssertionFunc
		errorSubstring string
		wantComparison int
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer, err := NewVersion("1.2.3", UnknownFormat)
				require.NoError(t, err)

				return thisVer, nil
			},
			expectError:    require.Error,
			errorSubstring: "no version provided for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.expectError == nil {
				test.expectError = require.NoError
			}
			thisVer, otherVer := test.setupFunc(t)

			n, err := thisVer.Compare(otherVer)
			test.expectError(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
			if err != nil {
				return
			}
			assert.Equal(t, test.wantComparison, n, "Expected comparison result to be %d", test.wantComparison)
		})
	}
}

func TestFuzzyVersion_Compare_NilScenarios(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(tb testing.TB) (fuzzyVersion, *Version)
		expectFallback bool // expect fuzzy comparison fallback
	}{
		{
			name: "both v.semVer and other semver are nil",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with nil semVer
				fv := fuzzyVersion{
					semVer: nil,
					raw:    "abc123",
				}

				otherVer, err := NewVersion("def456", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: true,
		},
		{
			name: "v.semVer is nil, other semver is not nil",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with nil semVer
				fv := fuzzyVersion{
					semVer: nil,
					raw:    "abc123",
				}

				otherVer, err := NewVersion("1.2.3", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: true,
		},
		{
			name: "v.semVer is not nil but v.semVer.obj is nil",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with semVer that has nil obj
				fv := fuzzyVersion{
					semVer: &semanticVersion{obj: nil},
					raw:    "abc123",
				}

				otherVer, err := NewVersion("1.2.3", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: true,
		},
		{
			name: "v.semVer is valid but other semver is nil",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with valid semVer
				semVer, err := newSemanticVersion("1.2.3", false)
				require.NoError(t, err)

				fv := fuzzyVersion{
					semVer: &semVer,
					raw:    "1.2.3",
				}

				// create other version that will result in nil semver from newFuzzySemver
				otherVer, err := NewVersion("abc123", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: true,
		},
		{
			name: "v.semVer is valid but other semver.obj is nil",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with valid semVer
				semVer, err := newSemanticVersion("1.2.3", false)
				require.NoError(t, err)

				fv := fuzzyVersion{
					semVer: &semVer,
					raw:    "1.2.3",
				}

				// this should create a version that when passed to newFuzzySemver
				// results in a semanticVersion with nil obj (this might be hard to achieve
				// but we'll test the logic path)
				otherVer, err := NewVersion("not-semver-compliant", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: true,
		},
		{
			name: "both semvers are valid - should use semver comparison",
			setupFunc: func(t testing.TB) (fuzzyVersion, *Version) {
				// create fuzzyVersion with valid semVer
				semVer, err := newSemanticVersion("1.2.3", false)
				require.NoError(t, err)

				fv := fuzzyVersion{
					semVer: &semVer,
					raw:    "1.2.3",
				}

				otherVer, err := NewVersion("1.2.4", UnknownFormat)
				require.NoError(t, err)

				return fv, otherVer
			},
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv, otherVer := tt.setupFunc(t)

			result, err := fv.Compare(otherVer)
			require.NoError(t, err)

			// verify that the result is a valid comparison result
			assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")

			// we can't easily test which path was taken without modifying the source,
			// but we can at least verify the function doesn't panic and returns valid results
			if tt.expectFallback {
				// when falling back to fuzzy comparison, we should get a result
				// the exact value depends on the fuzzyVersionComparison implementation
				assert.NotPanics(t, func() {
					_, _ = fv.Compare(otherVer)
				})
			}
		})
	}
}
