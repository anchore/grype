package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBitnamiVersion_Constraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// typical cases
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.2.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.0.1", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "= 2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "  =   2.3.1", satisfied: true},
		{version: "2.3.1", constraint: ">= 2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "> 2.0.0", satisfied: true},
		{version: "2.3.1", constraint: "> 2.0", satisfied: true},
		{version: "2.3.1", constraint: "> 2", satisfied: true},
		{version: "2.3.1", constraint: "> 2, < 3", satisfied: true},
		{version: "2.3.1", constraint: "> 2.3, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: "> 2.3.0, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: ">= 2.3.1, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: "  =  2.3.2", satisfied: false},
		{version: "2.3.1", constraint: ">= 2.3.2", satisfied: false},
		{version: "2.3.1", constraint: "> 2.3.1", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2", satisfied: false},
		{version: "2.3.1", constraint: "< 2, > 3", satisfied: false},
		{version: "2.3.1-1", constraint: "2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "= 2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "  =   2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: ">= 2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.0.0", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.0", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2, < 3", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.3, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.3.0, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: ">= 2.3.1, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "  =  2.3.2", satisfied: false},
		{version: "2.3.1-1", constraint: ">= 2.3.2", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2, > 3", satisfied: false},
		// ignoring revisions
		{version: "2.3.1-1", constraint: "> 2.3.1", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.3.1-2", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, BitnamiFormat)

			require.NoError(t, err)
			test.assertVersionConstraint(t, BitnamiFormat, constraint)
		})
	}
}

func TestBitnamiVersion_Compare(t *testing.T) {
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
			thisVersion:  "1.2.3-4",
			otherVersion: "1.2.3-5",
			otherFormat:  BitnamiFormat,
			expectError:  false,
		},
		{
			name:         "semantic versioning successful comparison",
			thisVersion:  "1.2.3-4",
			otherVersion: "1.2.3",
			otherFormat:  SemanticFormat,
			expectError:  false,
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
			errorSubstring: "invalid semantic version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newBitnamiVersion(test.thisVersion)
			require.NoError(t, err)

			otherVer := New(test.otherVersion, test.otherFormat)

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

func TestBitnamiVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := New("1.2.3-4", BitnamiFormat)

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
