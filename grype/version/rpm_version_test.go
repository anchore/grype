package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRpmVersion_Constraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// trivial compound conditions
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
		// trivial scenarios
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
		// epoch
		{version: "1:0", constraint: "< 0:1", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "<= 2:4.19.1-1.el7_5", satisfied: true},
		{version: "0:4.19.1-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: true},
		{version: "11:4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: true},
		{version: "13:4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: false},
		// regression: https://github.com/anchore/grype/issues/316
		{version: "1.5.4-2.el7_9", constraint: "< 0:1.5.4-2.el7_9", satisfied: false},
		{version: "1.5.4-2.el7", constraint: "< 0:1.5.4-2.el7_9", satisfied: true},
		// Non-standard epoch handling. In comparisons with epoch on only one side, they are both ignored
		{version: "1:0", constraint: "< 1", satisfied: true},
		{version: "0:0", constraint: "< 0", satisfied: false},
		{version: "0:0", constraint: "= 0", satisfied: true},
		{version: "0", constraint: "= 0:0", satisfied: true},
		{version: "1.0", constraint: "< 2:1.0", satisfied: false},
		{version: "1.0", constraint: "<= 2:1.0", satisfied: true},
		{version: "1:2", constraint: "< 1", satisfied: false},
		{version: "1:2", constraint: "> 1", satisfied: true},
		{version: "2:4.19.01-1.el7_5", constraint: "< 4.19.1-1.el7_5", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "<= 4.19.1-1.el7_5", satisfied: true},
		{version: "4.19.01-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: false},
		{version: "4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: false},
		{version: "4.19.0-1.el7_5", constraint: "<= 12:4.19.0-1.el7", satisfied: false},
		{version: "3:4.19.0-1.el7_5", constraint: "< 4.21.0-1.el7", satisfied: true},
		{version: "4:1.2.3-3-el7_5", constraint: "< 1.2.3-el7_5~snapshot1", satisfied: false},
		// regression https://github.com/anchore/grype/issues/398
		{version: "8.3.1-5.el8.4", constraint: "< 0:8.3.1-5.el8.5", satisfied: true},
		{version: "8.3.1-5.el8.40", constraint: "< 0:8.3.1-5.el8.5", satisfied: false},
		{version: "8.3.1-5.el8", constraint: "< 0:8.3.1-5.el8.0.0", satisfied: false},
		{version: "8.3.1-5.el8", constraint: "<= 0:8.3.1-5.el8.0.0", satisfied: true},
		{version: "8.3.1-5.el8.0.0", constraint: "> 0:8.3.1-5.el8", satisfied: false},
		{version: "8.3.1-5.el8.0.0", constraint: ">= 0:8.3.1-5.el8", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, RpmFormat)
			assert.NoError(t, err, "unexpected error from newRpmConstraint: %v", err)

			test.assertVersionConstraint(t, RpmFormat, constraint)
		})
	}
}

func TestRpmVersion_Compare(t *testing.T) {
	tests := []struct {
		v1     string
		v2     string
		result int
	}{
		// from https://github.com/anchore/anchore-engine/blob/a447ee951c2d4e17c2672553d7280cfdb5e5f193/tests/unit/anchore_engine/util/test_rpm.py
		{"1", "1", 0},
		{"4.19.0a-1.el7_5", "4.19.0c-1.el7", -1},
		{"4.19.0-1.el7_5", "4.21.0-1.el7", -1},
		{"4.19.01-1.el7_5", "4.19.10-1.el7_5", -1},
		{"4.19.0-1.el7_5", "4.19.0-1.el7", 1},
		{"4.19.0-1.el7_5", "4.17.0-1.el7", 1},
		{"4.19.01-1.el7_5", "4.19.1-1.el7_5", 0},
		{"4.19.1-1.el7_5", "4.19.1-01.el7_5", 0},
		{"4.19.1", "4.19.1", 0},
		{"1.2.3-el7_5~snapshot1", "1.2.3-3-el7_5", -1},
		{"1:0", "0:1", 1},
		{"1:2", "1", 1},
		{"0:4.19.1-1.el7_5", "2:4.19.1-1.el7_5", -1},
		{"4:1.2.3-3-el7_5", "1.2.3-el7_5~snapshot1", 1},

		// non-standard comparisons that ignore epochs due to only one being available
		{"1:0", "1", -1},
		{"2:4.19.01-1.el7_5", "4.19.1-1.el7_5", 0},
		{"4.19.01-1.el7_5", "2:4.19.1-1.el7_5", 0},
		{"4.19.0-1.el7_5", "12:4.19.0-1.el7", 1},
		{"3:4.19.0-1.el7_5", "4.21.0-1.el7", -1},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1 := New(test.v1, RpmFormat)
			v2 := New(test.v2, RpmFormat)

			actual, err := v1.Compare(v2)
			require.NoError(t, err, "unexpected error comparing versions: %s vs %s", test.v1, test.v2)
			assert.Equal(t, test.result, actual, "expected comparison result to match for %s vs %s", test.v1, test.v2)
		})
	}
}

func TestRpmVersion_Compare_Format(t *testing.T) {
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
			otherFormat:  RpmFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with epoch",
			thisVersion:  "1:1.2.3-1",
			otherVersion: "1:1.2.3-2",
			otherFormat:  RpmFormat,
			expectError:  false,
		},
		{
			name:         "unknown format attempts upgrade - valid rpm format",
			thisVersion:  "1.2.3-1",
			otherVersion: "1.2.3-2",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer := New(test.thisVersion, RpmFormat)

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

func TestRpmVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := New("1.2.3-1", RpmFormat)
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

func TestRpmVersion_CompareWithConfig(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		other    string
		strategy string
		want     int // -1, 0, or 1
	}{
		{
			name:     "package has epoch, no behavior change with auto",
			version:  "1:2.0.0",
			other:    "1:1.5.0",
			strategy: "auto",
			want:     1, // 1:2.0.0 > 1:1.5.0
		},
		{
			name:     "package has epoch, no behavior change with zero",
			version:  "1:2.0.0",
			other:    "1:1.5.0",
			strategy: "zero",
			want:     1, // 1:2.0.0 > 1:1.5.0
		},
		{
			name:     "package missing epoch, constraint has epoch, auto strategy - no match",
			version:  "2.0.0",
			other:    "1:1.5.0",
			strategy: "auto",
			want:     1, // Treated as 1:2.0.0 > 1:1.5.0
		},
		{
			name:     "package missing epoch, constraint has epoch, zero strategy",
			version:  "2.0.0",
			other:    "1:1.5.0",
			strategy: "zero",
			want:     1, // Epochs ignored when only one present: 2.0.0 > 1.5.0
		},
		{
			name:     "both missing epoch, auto strategy",
			version:  "2.0.0",
			other:    "1.5.0",
			strategy: "auto",
			want:     1, // 2.0.0 > 1.5.0
		},
		{
			name:     "both missing epoch, zero strategy",
			version:  "2.0.0",
			other:    "1.5.0",
			strategy: "zero",
			want:     1, // 2.0.0 > 1.5.0
		},
		{
			name:     "constraint missing epoch, package has epoch",
			version:  "1:2.0.0",
			other:    "1.5.0",
			strategy: "auto",
			want:     1, // 1:2.0.0 > 0:1.5.0 (constraint gets epoch 0)
		},
		{
			name:     "auto strategy, package less than constraint",
			version:  "1.0.0",
			other:    "1:1.5.0",
			strategy: "auto",
			want:     -1, // Treated as 1:1.0.0 < 1:1.5.0
		},
		{
			name:     "auto strategy, different epochs on constraints",
			version:  "1.2.0",
			other:    "2:1.5.0",
			strategy: "auto",
			want:     -1, // Treated as 2:1.2.0 < 2:1.5.0
		},
		{
			name:     "zero strategy, package version newer but lower epoch",
			version:  "3.0.0",
			other:    "1:1.0.0",
			strategy: "zero",
			want:     1, // Epochs ignored when only one present: 3.0.0 > 1.0.0
		},
		{
			name:     "auto strategy, equal versions different missing epochs",
			version:  "1.2.3",
			other:    "1:1.2.3",
			strategy: "auto",
			want:     0, // Treated as 1:1.2.3 == 1:1.2.3
		},
		{
			name:     "zero strategy, equal versions different missing epochs",
			version:  "1.2.3",
			other:    "1:1.2.3",
			strategy: "zero",
			want:     0, // Epochs ignored when only one present: 1.2.3 == 1.2.3
		},
		{
			name:     "auto strategy, large epoch difference",
			version:  "1.0.0",
			other:    "999:0.5.0",
			strategy: "auto",
			want:     1, // Treated as 999:1.0.0 > 999:0.5.0
		},
		{
			name:     "zero strategy, large epoch difference",
			version:  "1.0.0",
			other:    "999:0.5.0",
			strategy: "zero",
			want:     1, // Epochs ignored when only one present: 1.0.0 > 0.5.0
		},
		{
			name:     "both have epochs, strategy should not matter",
			version:  "2:1.5.0",
			other:    "1:2.0.0",
			strategy: "auto",
			want:     1, // 2:1.5.0 > 1:2.0.0 (epoch takes precedence)
		},
		{
			name:     "both have same epoch, strategy should not matter",
			version:  "3:2.0.0",
			other:    "3:1.5.0",
			strategy: "zero",
			want:     1, // 3:2.0.0 > 3:1.5.0
		},
		{
			name:     "empty strategy uses default behavior (zero-like)",
			version:  "2.0.0",
			other:    "1:1.5.0",
			strategy: "",
			want:     1, // Should behave like zero strategy: epochs ignored, 2.0.0 > 1.5.0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := newRpmVersion(tt.version)
			require.NoError(t, err)

			v2 := &Version{
				Format: RpmFormat,
				Raw:    tt.other,
			}

			cfg := ComparisonConfig{
				MissingEpochStrategy: tt.strategy,
			}

			result, err := v1.CompareWithConfig(v2, cfg)
			require.NoError(t, err)
			assert.Equal(t, tt.want, result,
				"comparing %s vs %s with strategy %s",
				tt.version, tt.other, tt.strategy)
		})
	}
}

func TestRpmVersion_CompareWithConfig_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		other    *Version
		strategy string
		wantErr  bool
	}{
		{
			name:     "nil other version",
			version:  "1.0.0",
			other:    nil,
			strategy: "auto",
			wantErr:  true,
		},
		{
			name:     "invalid other version format",
			version:  "1.0.0",
			other:    &Version{Format: RpmFormat, Raw: "not:a:valid:version:string:with:too:many:colons"},
			strategy: "auto",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := newRpmVersion(tt.version)
			require.NoError(t, err)

			cfg := ComparisonConfig{
				MissingEpochStrategy: tt.strategy,
			}

			_, err = v1.CompareWithConfig(tt.other, cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRpmVersion_CompareWithConfig_ConsistencyWithCompare(t *testing.T) {
	// Test that when both versions have epochs, CompareWithConfig gives same result as Compare
	tests := []struct {
		v1 string
		v2 string
	}{
		{"1:2.0.0", "1:1.5.0"},
		{"2:1.0.0", "1:2.0.0"},
		{"0:1.2.3", "0:1.2.3"},
		{"5:1.0.0-1.el7", "5:1.0.0-2.el7"},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			v1, _ := newRpmVersion(tt.v1)
			v2 := &Version{Format: RpmFormat, Raw: tt.v2}

			// Test with both strategies
			for _, strategy := range []string{"zero", "auto"} {
				cfg := ComparisonConfig{MissingEpochStrategy: strategy}

				resultWithConfig, err1 := v1.CompareWithConfig(v2, cfg)
				require.NoError(t, err1)

				resultNormal, err2 := v1.Compare(v2)
				require.NoError(t, err2)

				assert.Equal(t, resultNormal, resultWithConfig,
					"when both versions have epochs, CompareWithConfig should match Compare (strategy: %s)", strategy)
			}
		})
	}
}
