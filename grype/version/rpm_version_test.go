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
			v1, err := NewVersion(test.v1, RpmFormat)
			if err != nil {
				t.Fatalf("failed to create v1: %+v", err)
			}

			v2, err := NewVersion(test.v2, RpmFormat)
			if err != nil {
				t.Fatalf("failed to create v2: %+v", err)
			}

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
			thisVer, err := NewVersion(test.thisVersion, RpmFormat)
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
				thisVer, err := NewVersion("1.2.3-1", RpmFormat)
				require.NoError(t, err)
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
