package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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
		// epoch - both sides have epoch
		{version: "1:0", constraint: "< 0:1", satisfied: false},
		{version: "2:4.19.01-1", constraint: "< 2:4.19.1-1", satisfied: false},
		{version: "2:4.19.01-1", constraint: "<= 2:4.19.1-1", satisfied: true},
		{version: "0:4.19.1-1", constraint: "< 2:4.19.1-1", satisfied: true},
		{version: "11:4.19.0-1", constraint: "< 12:4.19.0-1", satisfied: true},
		{version: "13:4.19.0-1", constraint: "< 12:4.19.0-1", satisfied: false},
		// epoch - missing epoch treated as 0 (standard dpkg behavior)
		// This differs from RPM which ignores epochs when only one side has them
		{version: "1:0", constraint: "< 1", satisfied: false},                 // 1:0 vs 0:1 -> epoch 1 > 0, not satisfied
		{version: "0:0", constraint: "< 0", satisfied: false},                 // 0:0 vs 0:0 -> equal, not satisfied
		{version: "0:0", constraint: "= 0", satisfied: true},                  // 0:0 vs 0:0 -> equal
		{version: "0", constraint: "= 0:0", satisfied: true},                  // 0:0 vs 0:0 -> equal
		{version: "1.0", constraint: "< 2:1.0", satisfied: true},              // 0:1.0 vs 2:1.0 -> epoch 0 < 2, satisfied
		{version: "1.0", constraint: "<= 2:1.0", satisfied: true},             // 0:1.0 vs 2:1.0 -> epoch 0 < 2, satisfied
		{version: "1:2", constraint: "< 1", satisfied: false},                 // 1:2 vs 0:1 -> epoch 1 > 0, not satisfied
		{version: "1:2", constraint: "> 1", satisfied: true},                  // 1:2 vs 0:1 -> epoch 1 > 0, satisfied
		{version: "2:4.19.01-1", constraint: "< 4.19.1-1", satisfied: false},  // epoch 2 > 0
		{version: "2:4.19.01-1", constraint: "<= 4.19.1-1", satisfied: false}, // epoch 2 > 0
		{version: "4.19.01-1", constraint: "< 2:4.19.1-1", satisfied: true},   // epoch 0 < 2
		{version: "4.19.0-1", constraint: "< 12:4.19.0-1", satisfied: true},   // epoch 0 < 12
		{version: "4.19.0-1", constraint: "<= 12:4.19.0-1", satisfied: true},  // epoch 0 < 12
		{version: "3:4.19.0-1", constraint: "< 4.21.0-1", satisfied: false},   // epoch 3 > 0
		// real-world debian version formats with epochs
		{version: "1.5.4-2+deb9u1", constraint: "< 0:1.5.4-2+deb9u1", satisfied: false},
		{version: "1.5.4-2+deb9u1", constraint: "<= 0:1.5.4-2+deb9u1", satisfied: true},
		{version: "1.5.4-2+deb9u1", constraint: "< 1:1.5.4-2+deb9u1", satisfied: true}, // epoch 0 < 1
		{version: "8.3.1-5ubuntu1", constraint: "< 0:8.3.1-5ubuntu2", satisfied: true},
		{version: "8.3.1-5ubuntu1.40", constraint: "< 0:8.3.1-5ubuntu1.5", satisfied: false},
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
			name:         "with epochs",
			thisVersion:  "1:1.2.3-1",
			otherVersion: "1:1.2.3-2",
			otherFormat:  DebFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer := New(test.thisVersion, DebFormat)

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

func TestDebVersion_Compare_Epochs(t *testing.T) {
	// Test epoch comparison behavior - this is critical for vulnerability matching
	// The deb library treats missing epochs as 0, which differs from RPM behavior
	tests := []struct {
		name   string
		v1     string
		v2     string
		expect string // "less", "equal", "greater"
	}{
		// both have epochs - standard comparison
		{"epoch 1 vs 0, same version", "1:0", "0:1", "greater"},
		{"same epoch, different version", "1:2", "1:1", "greater"},
		{"different epochs, same version", "0:4.19.1-1", "2:4.19.1-1", "less"},
		{"equal with epochs", "2:1.0-1", "2:1.0-1", "equal"},

		// missing epoch treated as 0 (differs from RPM which ignores one-sided epochs)
		{"epoch 1 vs missing (treated as 0)", "1:0", "1", "greater"},    // 1:0 vs 0:1 -> epoch 1 > 0
		{"epoch 2 vs missing", "2:4.19.01-1", "4.19.1-1", "greater"},    // epoch 2 > 0
		{"missing vs epoch 2", "4.19.01-1", "2:4.19.1-1", "less"},       // epoch 0 < 2
		{"missing vs epoch 12", "4.19.0-1", "12:4.19.0-1", "less"},      // epoch 0 < 12
		{"epoch 3 vs missing", "3:4.19.0-1", "4.21.0-1", "greater"},     // epoch 3 > 0
		{"missing epoch equal to 0 epoch", "1.0-1", "0:1.0-1", "equal"}, // 0:1.0-1 == 0:1.0-1
		{"explicit 0 epoch vs missing", "0:1.0-1", "1.0-1", "equal"},    // 0:1.0-1 == 0:1.0-1

		// tilde behavior (not epoch-specific but important for deb)
		{"tilde sorts before everything", "1.0~rc1-1", "1.0-1", "less"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v1 := New(test.v1, DebFormat)
			v2 := New(test.v2, DebFormat)

			actual, err := v1.Compare(v2)
			require.NoError(t, err, "unexpected error comparing versions: %s vs %s", test.v1, test.v2)

			switch test.expect {
			case "less":
				assert.Less(t, actual, 0, "expected %s < %s", test.v1, test.v2)
			case "equal":
				assert.Equal(t, 0, actual, "expected %s == %s", test.v1, test.v2)
			case "greater":
				assert.Greater(t, actual, 0, "expected %s > %s", test.v1, test.v2)
			}
		})
	}
}

func TestDebVersion_CompareWithConfig(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		other    string
		strategy MissingEpochStrategy
		want     int // -1, 0, or 1
	}{
		{
			name:     "package has epoch, no behavior change with auto",
			version:  "1:2.0.0",
			other:    "1:1.5.0",
			strategy: MissingEpochStrategyAuto,
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
			strategy: MissingEpochStrategyAuto,
			want:     1, // Treated as 1:2.0.0 > 1:1.5.0
		},
		{
			name:     "package missing epoch, constraint has epoch, zero strategy - match",
			version:  "2.0.0",
			other:    "1:1.5.0",
			strategy: "zero",
			want:     -1, // Treated as 0:2.0.0 < 1:1.5.0
		},
		{
			name:     "both missing epoch, auto strategy",
			version:  "2.0.0",
			other:    "1.5.0",
			strategy: MissingEpochStrategyAuto,
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
			version:  "1:2.0.0-1",
			other:    "1.5.0-1",
			strategy: MissingEpochStrategyAuto,
			want:     1, // 1:2.0.0 > 0:1.5.0 (constraint gets epoch 0)
		},
		{
			name:     "auto strategy, package less than constraint",
			version:  "1.0.0",
			other:    "1:1.5.0",
			strategy: MissingEpochStrategyAuto,
			want:     -1, // Treated as 1:1.0.0 < 1:1.5.0
		},
		{
			name:     "auto strategy, different epochs on constraints",
			version:  "1.2.0",
			other:    "2:1.5.0",
			strategy: MissingEpochStrategyAuto,
			want:     -1, // Treated as 2:1.2.0 < 2:1.5.0
		},
		{
			name:     "zero strategy, package version newer but lower epoch",
			version:  "3.0.0",
			other:    "1:1.0.0",
			strategy: "zero",
			want:     -1, // 0:3.0.0 < 1:1.0.0 because epoch 0 < 1
		},
		{
			name:     "auto strategy, equal versions different missing epochs",
			version:  "1.2.3-1",
			other:    "1:1.2.3-1",
			strategy: MissingEpochStrategyAuto,
			want:     0, // Treated as 1:1.2.3 == 1:1.2.3
		},
		{
			name:     "zero strategy, equal versions different missing epochs",
			version:  "1.2.3-1",
			other:    "1:1.2.3-1",
			strategy: "zero",
			want:     -1, // 0:1.2.3 < 1:1.2.3
		},
		{
			name:     "auto strategy, large epoch difference",
			version:  "1.0.0",
			other:    "999:0.5.0",
			strategy: MissingEpochStrategyAuto,
			want:     1, // Treated as 999:1.0.0 > 999:0.5.0
		},
		{
			name:     "zero strategy, large epoch difference",
			version:  "1.0.0",
			other:    "999:0.5.0",
			strategy: "zero",
			want:     -1, // 0:1.0.0 < 999:0.5.0
		},
		{
			name:     "both have epochs, strategy should not matter",
			version:  "2:1.5.0-1",
			other:    "1:2.0.0-1",
			strategy: MissingEpochStrategyAuto,
			want:     1, // 2:1.5.0 > 1:2.0.0 (epoch takes precedence)
		},
		{
			name:     "both have same epoch, strategy should not matter",
			version:  "3:2.0.0-1",
			other:    "3:1.5.0-1",
			strategy: "zero",
			want:     1, // 3:2.0.0 > 3:1.5.0
		},
		{
			name:     "debian revision comparison with auto",
			version:  "1.0-1ubuntu1",
			other:    "1:1.0-1ubuntu1",
			strategy: MissingEpochStrategyAuto,
			want:     0, // Treated as 1:1.0-1ubuntu1 == 1:1.0-1ubuntu1
		},
		{
			name:     "empty strategy uses default behavior (zero-like)",
			version:  "2.0.0",
			other:    "1:1.5.0",
			strategy: "",
			want:     -1, // Should behave like zero strategy when empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := newDebVersion(tt.version)
			require.NoError(t, err)

			v2 := &Version{
				Format: DebFormat,
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

func TestDebVersion_CompareWithConfig_ErrorCases(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		other    *Version
		strategy MissingEpochStrategy
		wantErr  bool
	}{
		{
			name:     "nil other version",
			version:  "1.0.0",
			other:    nil,
			strategy: MissingEpochStrategyAuto,
			wantErr:  true,
		},
		{
			name:     "invalid other version format",
			version:  "1.0.0",
			other:    &Version{Format: DebFormat, Raw: "not-a-valid-debian-version!@#$%"},
			strategy: MissingEpochStrategyAuto,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v1, err := newDebVersion(tt.version)
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

func TestDebVersion_CompareWithConfig_ConsistencyWithCompare(t *testing.T) {
	// Test that when both versions have epochs, CompareWithConfig gives same result as Compare
	tests := []struct {
		v1 string
		v2 string
	}{
		{"1:2.0.0-1", "1:1.5.0-1"},
		{"2:1.0.0-1ubuntu1", "1:2.0.0-1ubuntu1"},
		{"0:1.2.3-1", "0:1.2.3-1"},
		{"5:1.0.0-1", "5:1.0.0-2"},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			v1, _ := newDebVersion(tt.v1)
			v2 := &Version{Format: DebFormat, Raw: tt.v2}

			// Test with both strategies
			for _, strategy := range []MissingEpochStrategy{MissingEpochStrategyZero, MissingEpochStrategyAuto} {
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

func TestExtractDebEpoch(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		wantNil  bool
		expected int
	}{
		{
			name:     "no epoch",
			version:  "1.2.3-1",
			wantNil:  true,
			expected: 0,
		},
		{
			name:     "epoch 0",
			version:  "0:1.2.3-1",
			wantNil:  false,
			expected: 0,
		},
		{
			name:     "epoch 1",
			version:  "1:1.2.3-1",
			wantNil:  false,
			expected: 1,
		},
		{
			name:     "large epoch",
			version:  "999:1.0.0",
			wantNil:  false,
			expected: 999,
		},
		{
			name:     "epoch with complex version",
			version:  "5:2.0.0-1ubuntu0.14.04.1",
			wantNil:  false,
			expected: 5,
		},
		{
			name:     "multiple colons - only first is epoch",
			version:  "1:2:3.4.5",
			wantNil:  false,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDebEpoch(tt.version)
			if tt.wantNil {
				assert.Nil(t, result, "expected nil epoch for version %s", tt.version)
			} else {
				require.NotNil(t, result, "expected non-nil epoch for version %s", tt.version)
				assert.Equal(t, tt.expected, *result, "epoch value mismatch for version %s", tt.version)
			}
		})
	}
}
