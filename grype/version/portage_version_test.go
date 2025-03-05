package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionPortage(t *testing.T) {
	tests := []struct {
		v1     string
		v2     string
		result int
	}{
		{"1", "1", 0},
		{"12.2.5", "12.2b", 1},
		{"12.2a", "12.2b", -1},
		{"12.2", "12.2.0", -1},
		{"1.01", "1.1", -1},
		{"1_p1", "1_p0", 1},
		{"1_p0", "1", 1},
		{"1-r1", "1", 1},
		{"1.2.3-r2", "1.2.3-r1", 1},
		{"1.2.3-r1", "1.2.3-r2", -1},
	}

	for _, test := range tests {
		name := test.v1 + "_vs_" + test.v2
		t.Run(name, func(t *testing.T) {
			v1 := newPortageVersion(test.v1)
			v2 := newPortageVersion(test.v2)

			actual := v1.compare(v2)

			if actual != test.result {
				t.Errorf("bad result: %+v (expected: %+v)", actual, test.result)
			}
		})
	}
}

func TestPortageVersionCompare_Format(t *testing.T) {
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
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  PortageFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with suffixes",
			thisVersion:  "1.2.3-r1",
			otherVersion: "1.2.3-r2",
			otherFormat:  PortageFormat,
			expectError:  false,
		},
		{
			name:           "different format returns error",
			thisVersion:    "1.2.3",
			otherVersion:   "1.2.3",
			otherFormat:    SemanticFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:           "different format returns error - apk",
			thisVersion:    "1.2.3",
			otherVersion:   "1.2.3-r4",
			otherFormat:    ApkFormat,
			expectError:    true,
			errorSubstring: "unsupported version format for comparison",
		},
		{
			name:         "unknown format attempts upgrade - valid portage format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer := newPortageVersion(test.thisVersion)

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

func TestPortageVersionCompareEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func() (*portageVersion, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func() (*portageVersion, *Version) {
				thisVer := newPortageVersion("1.2.3")
				return &thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
		{
			name: "empty portageVersion in other object",
			setupFunc: func() (*portageVersion, *Version) {
				thisVer := newPortageVersion("1.2.3")

				otherVer := &Version{
					Raw:    "1.2.4",
					Format: PortageFormat,
					rich:   rich{},
				}

				return &thisVer, otherVer
			},
			expectError:    true,
			errorSubstring: "given empty portageVersion object",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc()

			_, err := thisVer.Compare(otherVer)

			assert.Error(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
