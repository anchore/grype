package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemanticVersion_Constraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// typical cases
		{version: "0.9.9-r0", constraint: "< 0.9.12-r1", satisfied: true}, // regression case
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.2.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.0.1", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "= 2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "  =   2.3.1", satisfied: true},
		{version: "2.3.1", constraint: ">= 2.3.1", satisfied: true},
		{version: "2.3.1", constraint: "> 2.0.0", satisfied: true},
		{version: "2.3.1", constraint: "> 2.0", satisfied: true},
		{version: "2.3.1", constraint: "> 2", satisfied: true},
		{version: "2.3.1", constraint: "> 2, < 3", satisfied: true},
		{version: "2.3.1", constraint: "> 2.3, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: "> 2.3.0, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: ">= 2.3.1, < 3.1", satisfied: true},
		{version: "2.3.1", constraint: "  =  2.3.2", satisfied: false},
		{version: "2.3.1", constraint: ">= 2.3.2", satisfied: false},
		{version: "2.3.1", constraint: "> 2.3.1", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2", satisfied: false},
		{version: "2.3.1", constraint: "< 2, > 3", satisfied: false},
		{version: "2.3.1+meta", constraint: "2.3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: "= 2.3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: "  =   2.3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2.0.0", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2.0", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2, < 3", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2.3, < 3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: "> 2.3.0, < 3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1, < 3.1", satisfied: true},
		{version: "2.3.1+meta", constraint: "  =  2.3.2", satisfied: false},
		{version: "2.3.1+meta", constraint: ">= 2.3.2", satisfied: false},
		{version: "2.3.1+meta", constraint: "> 2.3.1", satisfied: false},
		{version: "2.3.1+meta", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1+meta", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1+meta", constraint: "< 2", satisfied: false},
		{version: "2.3.1+meta", constraint: "< 2, > 3", satisfied: false},
		// from https://github.com/hashicorp/go-version/issues/61
		// and https://semver.org/#spec-item-11
		// A larger set of pre-release fields has a higher precedence than a smaller set, if all of the preceding identifiers are equal.
		{version: "1.0.0-alpha", constraint: "> 1.0.0-alpha.1", satisfied: false},
		{version: "1.0.0-alpha", constraint: "< 1.0.0-alpha.1", satisfied: true},
		{version: "1.0.0-alpha.1", constraint: "> 1.0.0-alpha.beta", satisfied: false},
		{version: "1.0.0-alpha.1", constraint: "< 1.0.0-alpha.beta", satisfied: true},
		{version: "1.0.0-alpha.beta", constraint: "> 1.0.0-beta", satisfied: false},
		{version: "1.0.0-alpha.beta", constraint: "< 1.0.0-beta", satisfied: true},
		{version: "1.0.0-beta", constraint: "> 1.0.0-beta.2", satisfied: false},
		{version: "1.0.0-beta", constraint: "< 1.0.0-beta.2", satisfied: true},
		{version: "1.0.0-beta.2", constraint: "> 1.0.0-beta.11", satisfied: false},
		{version: "1.0.0-beta.2", constraint: "< 1.0.0-beta.11", satisfied: true},
		{version: "1.0.0-beta.11", constraint: "> 1.0.0-rc.1", satisfied: false},
		{version: "1.0.0-beta.11", constraint: "< 1.0.0-rc.1", satisfied: true},
		{version: "1.0.0-rc.1", constraint: "> 1.0.0", satisfied: false},
		{version: "1.0.0-rc.1", constraint: "< 1.0.0", satisfied: true},
		{version: "1.20rc1", constraint: " = 1.20.0-rc1", satisfied: true},
		{version: "1.21rc2", constraint: " = 1.21.1", satisfied: false},
		{version: "1.21rc2", constraint: " = 1.21", satisfied: false},
		{version: "1.21rc2", constraint: " = 1.21-rc2", satisfied: true},
		{version: "1.21rc2", constraint: " = 1.21.0-rc2", satisfied: true},
		{version: "1.21rc2", constraint: " = 1.21.0rc2", satisfied: true},
		{version: "1.0.0-alpha.1", constraint: "> 1.0.0-alpha.1", satisfied: false},
		{version: "1.0.0-alpha.2", constraint: "> 1.0.0-alpha.1", satisfied: true},
		{version: "1.2.0-beta", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-beta", constraint: ">1.0", satisfied: true},
		{version: "1.2.0-beta", constraint: "<2.0", satisfied: true},
		{version: "1.2.0", constraint: ">1.0, <2.0", satisfied: true},

		// below are test cases for the ruby version normalizer that converts .alpha, .beta, .rc to -alpha, -beta, -rc

		// prerelease normalizer - alpha versions
		{version: "1.0.0.alpha", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.alpha", constraint: "> 1.0.0-alpha", satisfied: false}, // should be equal after normalization
		{version: "1.0.0.alpha", constraint: "= 1.0.0-alpha", satisfied: true},
		{version: "1.0.0.alpha1", constraint: "= 1.0.0-alpha1", satisfied: true},
		{version: "1.0.0.alpha.1", constraint: "= 1.0.0-alpha.1", satisfied: true},

		// prerelease normalizer - beta versions
		{version: "1.0.0.beta", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.beta", constraint: "> 1.0.0-alpha", satisfied: true},
		{version: "1.0.0.beta", constraint: "= 1.0.0-beta", satisfied: true},
		{version: "1.0.0.beta2", constraint: "= 1.0.0-beta2", satisfied: true},
		{version: "1.0.0.beta.2", constraint: "= 1.0.0-beta.2", satisfied: true},

		// prerelease normalizer - rc versions
		{version: "1.0.0.rc", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.rc", constraint: "> 1.0.0-beta", satisfied: true},
		{version: "1.0.0.rc", constraint: "= 1.0.0-rc", satisfied: true},
		{version: "1.0.0.rc1", constraint: "= 1.0.0-rc1", satisfied: true},
		{version: "1.0.0.rc.1", constraint: "= 1.0.0-rc.1", satisfied: true},

		// prerelease normalizer - ordering tests to ensure normalization doesn't break semver precedence
		{version: "1.0.0.alpha", constraint: "< 1.0.0-beta", satisfied: true},
		{version: "1.0.0.beta", constraint: "< 1.0.0-rc", satisfied: true},
		{version: "1.0.0.rc", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.alpha1", constraint: "< 1.0.0-alpha2", satisfied: true},

		// prerelease normalizer - mixed ruby and standard semver styles in constraints
		{version: "1.0.0.alpha", constraint: "< 1.0.0-beta", satisfied: true},
		{version: "1.0.0-alpha", constraint: "< 1.0.0-beta", satisfied: true},

		// prerelease normalizer - complex constraints with ruby-style versions
		{version: "1.0.0.alpha", constraint: "> 0.9.0, < 1.0.0", satisfied: true},
		{version: "1.0.0.beta", constraint: "> 1.0.0-alpha, < 1.0.0", satisfied: true},
		{version: "2.1.0.rc1", constraint: "> 2.0.0, < 2.1.0", satisfied: true},

		// prerelease normalizer - edge cases
		{version: "1.0.0.alpha.beta", constraint: "= 1.0.0-alpha-beta", satisfied: true}, // multiple replacements
		{version: "1.0.0.rc.alpha", constraint: "= 1.0.0-rc-alpha", satisfied: true},     // mixed order

		// prerelease normalizer - ensure regular versions still work
		{version: "1.0.0-alpha", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0-beta", constraint: "> 1.0.0-alpha", satisfied: true},
		{version: "1.0.0-rc", constraint: "> 1.0.0-beta", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, SemanticFormat)
			assert.NoError(t, err)

			test.assertVersionConstraint(t, SemanticFormat, constraint)
		})
	}
}

func TestSemanticVersion_PrereleaseNormalizer_EdgeCases(t *testing.T) {
	// test edge cases to ensure the normalizer can be safely retained
	tests := []struct {
		name      string
		version   string
		wantError require.ErrorAssertionFunc
	}{
		{
			name:      "version with only alpha",
			version:   "alpha",
			wantError: require.Error, // invalid semver
		},
		{
			name:      "version with leading alpha",
			version:   "alpha.1.0.0",
			wantError: require.Error, // invalid semver
		},
		{
			name:      "empty version",
			version:   "",
			wantError: require.Error,
		},
		{
			name:    "version with multiple dots in prerelease",
			version: "1.0.0.alpha.beta.rc", // should normalize to 1.0.0-alpha-beta-rc
		},
		{
			name:    "version already in correct format",
			version: "1.0.0-alpha",
		},
		{
			name:    "version with build metadata",
			version: "1.0.0.alpha+build",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.wantError == nil {
				test.wantError = require.NoError
			}
			_, err := newSemanticVersion(test.version, false)
			test.wantError(t, err, "expected error for version: %s", test.version)
		})
	}
}

func TestSemanticVersion_PrereleaseNormalizer_WithGemFormat(t *testing.T) {
	// ensure that the prerelease normalizer in semantic format doesn't conflict with gem format
	rubyStyleVersions := []string{
		"1.0.0.alpha",
		"1.0.0.beta.1",
		"1.0.0.rc2",
	}

	for _, version := range rubyStyleVersions {
		t.Run(version, func(t *testing.T) {
			// both semantic and gem formats should be able to handle these versions
			semanticVer := New(version, SemanticFormat)
			gemVer := New(version, GemFormat)

			// they might have different comparison behavior, but both should be valid
			assert.NotNil(t, semanticVer)
			assert.NotNil(t, gemVer)
		})
	}
}

func TestSemanticVersion_Compare_Format(t *testing.T) {
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
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with prerelease",
			thisVersion:  "1.2.3-alpha",
			otherVersion: "1.2.3-beta",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with build metadata",
			thisVersion:  "1.2.3+build.1",
			otherVersion: "1.2.3+build.2",
			otherFormat:  SemanticFormat,
			expectError:  false,
		},
		{
			name:         "unknown format attempts upgrade - valid semantic format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid semantic format",
			thisVersion:    "1.2.3",
			otherVersion:   "not.valid.semver",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newSemanticVersion(test.thisVersion, true)
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
				assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
			}
		})
	}
}

func TestSemanticVersion_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := New("1.2.3", SemanticFormat)
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
