package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPortageVersion_Constraint(t *testing.T) {
	tests := []testCase{
		// empty constraint is always satisfied
		{version: "1.2.3", constraint: "", satisfied: true},
		{version: "1.2.3-r1", constraint: "", satisfied: true},
		{version: "1.2.3_alpha1", constraint: "", satisfied: true},

		// simple equality
		{version: "1.2.3", constraint: "= 1.2.3", satisfied: true},
		{version: "1.2.3-r1", constraint: "= 1.2.3-r1", satisfied: true},
		{version: "1.2.3", constraint: "= 1.2.4", satisfied: false},

		// less than
		{version: "1.2.3", constraint: "< 1.2.4", satisfied: true},
		{version: "1.2.3", constraint: "< 1.2.3", satisfied: false},
		{version: "1.2.3", constraint: "< 1.2.2", satisfied: false},
		{version: "1.2.3-r1", constraint: "< 1.2.3-r2", satisfied: true},
		{version: "1.2.3-r2", constraint: "< 1.2.3-r1", satisfied: false},

		// less than or equal
		{version: "1.2.3", constraint: "<= 1.2.3", satisfied: true},
		{version: "1.2.3", constraint: "<= 1.2.4", satisfied: true},
		{version: "1.2.3", constraint: "<= 1.2.2", satisfied: false},
		{version: "1.2.3-r1", constraint: "<= 1.2.3-r1", satisfied: true},

		// greater than
		{version: "1.2.4", constraint: "> 1.2.3", satisfied: true},
		{version: "1.2.3", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.2", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.3-r2", constraint: "> 1.2.3-r1", satisfied: true},
		{version: "1.2.3-r1", constraint: "> 1.2.3-r2", satisfied: false},

		// greater than or equal
		{version: "1.2.3", constraint: ">= 1.2.3", satisfied: true},
		{version: "1.2.4", constraint: ">= 1.2.3", satisfied: true},
		{version: "1.2.2", constraint: ">= 1.2.3", satisfied: false},
		{version: "1.2.3-r1", constraint: ">= 1.2.3-r1", satisfied: true},

		// compound conditions with AND (comma)
		{version: "1.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.2.3-r5", constraint: ">= 1.2.3-r1, <= 1.2.3-r10", satisfied: true},

		// compound conditions with OR
		{version: "0.5.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: true},
		{version: "3.0.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: true},
		{version: "1.5.0", constraint: "< 1.0.0 || > 2.0.0", satisfied: false},

		// complex compound conditions
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.3.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.8.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},

		// portage-specific version features
		// letter suffixes (a, b, c etc.)
		{version: "1.2a", constraint: "< 1.2b", satisfied: true},
		{version: "1.2b", constraint: "< 1.2a", satisfied: false},
		{version: "12.2.5", constraint: "> 12.2b", satisfied: true},

		// revision numbers (-r suffix)
		{version: "1.0.0-r1", constraint: "> 1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "> 1.0.0-r1", satisfied: false},
		{version: "1.2.3-r2", constraint: "> 1.2.3-r1", satisfied: true},
		{version: "1.2.3-r1", constraint: "< 1.2.3-r2", satisfied: true},

		// version suffixes (alpha, beta, pre, rc, p)
		{version: "1.0.0_alpha1", constraint: "< 1.0.0_beta1", satisfied: true},
		{version: "1.0.0_beta1", constraint: "< 1.0.0_rc1", satisfied: true},
		{version: "1.0.0_rc1", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "< 1.0.0_p1", satisfied: true},
		{version: "1.0.0_pre1", constraint: "> 1.0.0_alpha1", satisfied: true},

		// patch level suffixes
		{version: "1_p1", constraint: "> 1_p0", satisfied: true},
		{version: "1_p0", constraint: "> 1", satisfied: true},

		// decimal versions with leading zeros
		{version: "1.01", constraint: "< 1.1", satisfied: true},
		{version: "1.1", constraint: "> 1.01", satisfied: true},

		// version with missing patch components
		{version: "12.2", constraint: "< 12.2.0", satisfied: true}, // 12.2 < 12.2.0 is true in portage 🤯
		{version: "12.2.0", constraint: "> 12.2", satisfied: true},

		// edge cases - versions that should not match
		{version: "1.2.3", constraint: "= 1.2.4", satisfied: false},
		{version: "1.2.3", constraint: "> 1.2.3", satisfied: false},
		{version: "1.2.3", constraint: "< 1.2.3", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			test.assertVersionConstraint(t, PortageFormat, constraint)
		})
	}
}

func TestPortageConstraint_Constraint_NilVersion(t *testing.T) {
	tests := []struct {
		name        string
		constraint  string
		expected    bool
		shouldError bool
	}{
		{
			name:        "empty constraint with nil version",
			constraint:  "",
			expected:    true,
			shouldError: false,
		},
		{
			name:        "non-empty constraint with nil version",
			constraint:  "> 1.0.0",
			expected:    false,
			shouldError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			satisfied, err := c.Satisfied(nil)
			if test.shouldError {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, satisfied)
			}
		})
	}
}

func TestPortageConstraint_String(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		expected   string
	}{
		{
			name:       "empty constraint",
			constraint: "",
			expected:   "none (portage)",
		},
		{
			name:       "simple constraint",
			constraint: "> 1.0.0",
			expected:   "> 1.0.0 (portage)",
		},
		{
			name:       "complex constraint",
			constraint: "> 1.0.0, < 2.0.0",
			expected:   "> 1.0.0, < 2.0.0 (portage)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, PortageFormat)
			assert.NoError(t, err)

			result := constraint.String()
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestPortageVersion_Compare(t *testing.T) {
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
			v1 := New(test.v1, PortageFormat)
			v2 := New(test.v2, PortageFormat)

			actual, err := v1.Compare(v2)
			require.NoError(t, err)
			assert.Equal(t, test.result, actual, "expected comparison result to match")
		})
	}
}

func TestPortageVersion_Compare_Format(t *testing.T) {
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
			name:         "unknown format attempts upgrade - valid portage format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer := New(test.thisVersion, PortageFormat)
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

func TestPortageVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := New("1.2.3", PortageFormat)
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

func TestPortageVersion_WithoutNumericComponent(t *testing.T) {
	// every portage version carries a numeric component, so versionRegexp finds nothing in
	// values like these. that no-match result used to be indexed unconditionally, which
	// panicked. the matcher recovers matcher panics into a fatal error, and the fatal path
	// throws away every match collected so far, so one such package took down the whole scan
	// instead of just being skipped.
	nonNumeric := []string{"none", "latest", "rolling", "stable", "git", "N/A", "abc"}

	for _, raw := range nonNumeric {
		t.Run("package version "+raw, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := New(raw, PortageFormat).Compare(New("1.2.3", PortageFormat))
				require.ErrorContains(t, err, "no numeric version component")
			})
		})

		t.Run("compared-against version "+raw, func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := New("1.2.3", PortageFormat).Compare(New(raw, PortageFormat))
				require.ErrorContains(t, err, "no numeric version component")
			})
		})

		t.Run("constraint check "+raw, func(t *testing.T) {
			constraint, err := GetConstraint("< 1.2.3", PortageFormat)
			require.NoError(t, err)

			require.NotPanics(t, func() {
				_, err := constraint.Satisfied(New(raw, PortageFormat))
				require.Error(t, err)
			})
		})
	}
}

func TestPortageVersion_NumericComponentStillAccepted(t *testing.T) {
	// guards against the rejection above being tightened into something that turns away
	// versions portage does accept. the check reuses versionRegexp unanchored, so anything
	// that compared successfully before still does.
	accepted := []string{"1", "1.2.3", "1.2.3-r1", "1.2.3_alpha1", "1.2.3b", "12.2", "a1"}

	for _, raw := range accepted {
		t.Run(raw, func(t *testing.T) {
			_, err := newPortageVersion(raw)
			require.NoError(t, err)

			_, err = New(raw, PortageFormat).Compare(New("1.2.3", PortageFormat))
			require.NoError(t, err)
		})
	}
}
