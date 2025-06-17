package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionRpm(t *testing.T) {
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
		//Non-standard comparisons that ignore epochs due to only one being available
		{"1:0", "1", -1},
		{"2:4.19.01-1.el7_5", "4.19.1-1.el7_5", 0},
		{"4.19.01-1.el7_5", "2:4.19.1-1.el7_5", 0},
		{"4.19.0-1.el7_5", "12:4.19.0-1.el7", 1},
		{"3:4.19.0-1.el7_5", "4.21.0-1.el7", -1},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1, err := newRpmVersion(test.v1)
			if err != nil {
				t.Fatalf("failed to create v1: %+v", err)
			}

			v2, err := newRpmVersion(test.v2)
			if err != nil {
				t.Fatalf("failed to create v2: %+v", err)
			}

			actual := v1.compare(v2)

			if actual != test.result {
				t.Errorf("bad result: %+v (expected: %+v)", actual, test.result)
			}
		})
	}
}

func TestRpmVersionCompare_Format(t *testing.T) {
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

func TestRpmVersionCompareEdgeCases(t *testing.T) {
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
