package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDebVersion_Constraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// compound conditions
		{version: "2.3.1", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.3.1", constraint: "> 1.0.0, < 2.0.0", satisfied: true},
		{version: "2.0.0", constraint: "> 1.0.0, <= 2.0.0", satisfied: true},
		{version: "2.0.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.0.0", constraint: ">= 1.0.0, < 2.0.0", satisfied: true},
		{version: "1.0.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.9.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.2.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.0.1", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		// fixed-in scenarios
		{version: "2.3.1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3.1", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3.2", satisfied: true},
		{version: "2.3.1", constraint: "< 2.4", satisfied: true},
		{version: "2.3.1", constraint: "< 3", satisfied: true},
		{version: "2.3.1", constraint: "< 3.0", satisfied: true},
		{version: "2.3.1", constraint: "< 3.0.0", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0.0", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.1", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.2", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.4", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0.0", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11-2ubuntu0.14.04.1", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.7", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u150", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152-2.6.11-2ubuntu0.14.04.1", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 8u1-2.6.11-2ubuntu0.14.04.1", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81-0ubuntu0.14.04.1.1089", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.82-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2358-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.1-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<44-0ubuntu0.14.04.1.1089", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, DebFormat)
			require.NoError(t, err, "unexpected error from GetConstraint: %v", err)

			test.assertVersionConstraint(t, DebFormat, constraint)
		})
	}
}

func TestDebVersion_Compare(t *testing.T) {
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

			otherVer := NewVersion(test.otherVersion, test.otherFormat)

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

func TestDebVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := NewVersion("1.2.3-1", DebFormat)
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty debVersion in other object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := NewVersion("1.2.3-1", DebFormat)
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
