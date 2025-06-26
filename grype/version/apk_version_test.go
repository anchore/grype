package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApkVersion_Constraint(t *testing.T) {
	tests := []testCase{
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
		// alpine specific scenarios
		// https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver
		{version: "1.5.1-r1", constraint: "< 1.5.1", satisfied: false},
		{version: "1.5.1-r1", constraint: "> 1.5.1", satisfied: true},
		{version: "9.3.2-r4", constraint: "< 9.3.4-r2", satisfied: true},
		{version: "9.3.4-r2", constraint: "> 9.3.4", satisfied: true},
		{version: "4.2.52_p2-r1", constraint: "< 4.2.52_p4-r2", satisfied: true},
		{version: "4.2.52_p2-r1", constraint: "> 4.2.52_p4-r2", satisfied: false},
		{version: "0.1.0_alpha", constraint: "< 0.1.3_alpha", satisfied: true},
		{version: "0.1.0_alpha2", constraint: "> 0.1.0_alpha", satisfied: true},
		{version: "1.1", constraint: "> 1.1_alpha1", satisfied: true},
		{version: "1.1", constraint: "< 1.1_alpha1", satisfied: false},
		{version: "2.3.0b-r1", constraint: "< 2.3.0b-r2", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, ApkFormat)

			assert.NoError(t, err, "unexpected error from newApkConstraint: %v", err)
			test.assertVersionConstraint(t, ApkFormat, constraint)

		})
	}
}

func TestApkVersion_Compare(t *testing.T) {
	tests := []struct {
		name           string
		thisVersion    string
		otherVersion   string
		otherFormat    Format
		expectError    bool
		errorSubstring string
	}{
		{
			name:         "same Fmt successful comparison",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  ApkFormat,
			expectError:  false,
		},
		{
			name:         "different Fmt does not return error",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:           "different Fmt does not return error - deb",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "1.2.3-1",
			otherFormat:    DebFormat,
			expectError:    false,
			errorSubstring: "unsupported version comparison",
		},
		{
			name:         "unknown Fmt attempts upgrade - valid apk Fmt",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown Fmt attempts upgrade - invalid apk Fmt",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "not-valid-apk-Fmt",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "invalid version",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newApkVersion(test.thisVersion)
			require.NoError(t, err)

			otherVer := NewVersion(test.otherVersion, test.otherFormat)

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

func TestApkVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := NewVersion("1.2.3-r4", ApkFormat)
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
