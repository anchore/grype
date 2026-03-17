package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func intRef(i int) *int {
	return &i
}

func TestTrimLeadingV(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "lowercase v followed by digit",
			input: "v1.5.0",
			want:  "1.5.0",
		},
		{
			name:  "uppercase V followed by digit",
			input: "V1.5.0",
			want:  "1.5.0",
		},
		{
			name:  "no prefix",
			input: "1.5.0",
			want:  "1.5.0",
		},
		{
			name:  "v not followed by digit",
			input: "version1.0",
			want:  "version1.0",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "single v",
			input: "v",
			want:  "v",
		},
		{
			name:  "v followed by non-digit",
			input: "va.b.c",
			want:  "va.b.c",
		},
		{
			name:  "double v prefix",
			input: "vv1.0.0",
			want:  "vv1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimLeadingV(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

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
		expectResult   *int // nil means don't check specific result
	}{
		{
			name:         "same format successful comparison",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  ApkFormat,
			expectError:  false,
		},
		{
			name:         "different format does not return error",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:           "different format does not return error - deb",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "1.2.3-1",
			otherFormat:    DebFormat,
			expectError:    false,
			errorSubstring: "unsupported version comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid apk format",
			thisVersion:  "1.2.3-r4",
			otherVersion: "1.2.3-r5",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid apk format",
			thisVersion:    "1.2.3-r4",
			otherVersion:   "not-valid-apk-format",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "invalid version",
		},
		{
			name:         "lowercase v prefix on other version is stripped",
			thisVersion:  "1.5.0",
			otherVersion: "v1.5.0",
			otherFormat:  ApkFormat,
			expectResult: intRef(0),
		},
		{
			name:         "uppercase V prefix on other version is stripped",
			thisVersion:  "1.5.0",
			otherVersion: "V1.5.0",
			otherFormat:  ApkFormat,
			expectResult: intRef(0),
		},
		{
			name:         "v prefix on this version is stripped",
			thisVersion:  "v1.5.0",
			otherVersion: "1.5.0",
			otherFormat:  ApkFormat,
			expectResult: intRef(0),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newApkVersion(test.thisVersion)
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
				if test.expectResult != nil {
					assert.Equal(t, *test.expectResult, result)
				} else {
					assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
				}
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
				thisVer := New("1.2.3-r4", ApkFormat)
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
