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

func TestApkVersion_CompareWithConfig(t *testing.T) {
	tests := []struct {
		name     string
		pkg      string
		other    string
		strategy MissingApkReleaseStrategy
		want     int
	}{
		// the case that motivates the strategy: an SBOM drops "-r0" from the first fixed build
		{name: "strict: bare sorts below -r0", pkg: "3.6.3", other: "3.6.3-r0", strategy: MissingApkReleaseStrategyStrict, want: -1},
		{name: "empty: same as strict", pkg: "3.6.3", other: "3.6.3-r0", strategy: "", want: -1},
		{name: "zero: bare equals -r0", pkg: "3.6.3", other: "3.6.3-r0", strategy: MissingApkReleaseStrategyZero, want: 0},
		// a fix shipped as a rebuild of the same upstream version
		{name: "zero: bare is below a later rebuild", pkg: "3.6.3", other: "3.6.3-r4", strategy: MissingApkReleaseStrategyZero, want: -1},
		// the upstream version still decides when it differs
		{name: "zero: older upstream stays below", pkg: "3.6.2", other: "3.6.3-r0", strategy: MissingApkReleaseStrategyZero, want: -1},
		{name: "zero: newer upstream stays above", pkg: "3.6.4", other: "3.6.3-r9", strategy: MissingApkReleaseStrategyZero, want: 1},
		// only the package side is filled in
		{name: "zero: package with release is untouched", pkg: "3.6.3-r1", other: "3.6.3-r2", strategy: MissingApkReleaseStrategyZero, want: -1},
		{name: "zero: bare constraint is untouched", pkg: "3.6.3-r0", other: "3.6.3", strategy: MissingApkReleaseStrategyZero, want: 1},
		{name: "zero: both bare", pkg: "3.6.3", other: "3.6.3", strategy: MissingApkReleaseStrategyZero, want: 0},
		{name: "zero: leading v on the package", pkg: "v3.6.3", other: "3.6.3-r0", strategy: MissingApkReleaseStrategyZero, want: 0},
		{name: "zero: suffixed upstream version", pkg: "9.10.4_p3", other: "9.10.4_p3-r0", strategy: MissingApkReleaseStrategyZero, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := newApkVersion(tt.pkg)
			require.NoError(t, err)

			got, err := v.CompareWithConfig(New(tt.other, ApkFormat), ComparisonConfig{MissingApkReleaseStrategy: tt.strategy})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// the same result through Version.Compare, which honors the embedded config
			got, err = NewWithConfig(tt.pkg, ApkFormat, ComparisonConfig{MissingApkReleaseStrategy: tt.strategy}).Compare(New(tt.other, ApkFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestApkVersion_ConstraintWithConfig(t *testing.T) {
	tests := []struct {
		name       string
		pkg        string
		constraint string
		strategy   MissingApkReleaseStrategy
		satisfied  bool
	}{
		{name: "strict: bare first fixed build is vulnerable", pkg: "3.6.3", constraint: "< 3.6.3-r0", strategy: MissingApkReleaseStrategyStrict, satisfied: true},
		{name: "zero: bare first fixed build is fixed", pkg: "3.6.3", constraint: "< 3.6.3-r0", strategy: MissingApkReleaseStrategyZero, satisfied: false},
		{name: "zero: bare is vulnerable to a rebuild fix", pkg: "3.6.3", constraint: "< 3.6.3-r4", strategy: MissingApkReleaseStrategyZero, satisfied: true},
		{name: "zero: NAK never matches", pkg: "3.6.3", constraint: "< 0", strategy: MissingApkReleaseStrategyZero, satisfied: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := GetConstraint(tt.constraint, ApkFormat)
			require.NoError(t, err)

			got, err := c.Satisfied(NewWithConfig(tt.pkg, ApkFormat, ComparisonConfig{MissingApkReleaseStrategy: tt.strategy}))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}
