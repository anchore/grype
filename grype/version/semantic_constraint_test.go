package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_SemanticConstraint(t *testing.T) {
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
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, SemanticFormat)
			assert.NoError(t, err)

			test.assertVersionConstraint(t, SemanticFormat, constraint)
		})
	}
}

func TestSemanticConstraint_PrereleaseNormalizer(t *testing.T) {
	// test cases for the ruby version normalizer that converts .alpha, .beta, .rc to -alpha, -beta, -rc
	tests := []testCase{
		// alpha versions
		{version: "1.0.0.alpha", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.alpha", constraint: "> 1.0.0-alpha", satisfied: false}, // should be equal after normalization
		{version: "1.0.0.alpha", constraint: "= 1.0.0-alpha", satisfied: true},
		{version: "1.0.0.alpha1", constraint: "= 1.0.0-alpha1", satisfied: true},
		{version: "1.0.0.alpha.1", constraint: "= 1.0.0-alpha.1", satisfied: true},

		// beta versions
		{version: "1.0.0.beta", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.beta", constraint: "> 1.0.0-alpha", satisfied: true},
		{version: "1.0.0.beta", constraint: "= 1.0.0-beta", satisfied: true},
		{version: "1.0.0.beta2", constraint: "= 1.0.0-beta2", satisfied: true},
		{version: "1.0.0.beta.2", constraint: "= 1.0.0-beta.2", satisfied: true},

		// rc versions
		{version: "1.0.0.rc", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.rc", constraint: "> 1.0.0-beta", satisfied: true},
		{version: "1.0.0.rc", constraint: "= 1.0.0-rc", satisfied: true},
		{version: "1.0.0.rc1", constraint: "= 1.0.0-rc1", satisfied: true},
		{version: "1.0.0.rc.1", constraint: "= 1.0.0-rc.1", satisfied: true},

		// ordering tests to ensure normalization doesn't break semver precedence
		{version: "1.0.0.alpha", constraint: "< 1.0.0-beta", satisfied: true},
		{version: "1.0.0.beta", constraint: "< 1.0.0-rc", satisfied: true},
		{version: "1.0.0.rc", constraint: "< 1.0.0", satisfied: true},
		{version: "1.0.0.alpha1", constraint: "< 1.0.0-alpha2", satisfied: true},

		// mixed ruby and standard semver styles in constraints
		{version: "1.0.0.alpha", constraint: "< 1.0.0-beta", satisfied: true},
		{version: "1.0.0-alpha", constraint: "< 1.0.0-beta", satisfied: true},

		// complex constraints with ruby-style versions
		{version: "1.0.0.alpha", constraint: "> 0.9.0, < 1.0.0", satisfied: true},
		{version: "1.0.0.beta", constraint: "> 1.0.0-alpha, < 1.0.0", satisfied: true},
		{version: "2.1.0.rc1", constraint: "> 2.0.0, < 2.1.0", satisfied: true},

		// edge cases
		{version: "1.0.0.alpha.beta", constraint: "= 1.0.0-alpha-beta", satisfied: true}, // multiple replacements
		{version: "1.0.0.rc.alpha", constraint: "= 1.0.0-rc-alpha", satisfied: true},     // mixed order

		// ensure regular versions still work
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

func TestSemanticConstraint_RubyNormalizerEdgeCases(t *testing.T) {
	// Test edge cases to ensure the normalizer can be safely retained
	tests := []struct {
		name        string
		version     string
		shouldError bool
	}{
		{
			name:        "version with only alpha",
			version:     "alpha",
			shouldError: true, // invalid semver
		},
		{
			name:        "version with leading alpha",
			version:     "alpha.1.0.0",
			shouldError: true, // invalid semver
		},
		{
			name:        "empty version",
			version:     "",
			shouldError: true,
		},
		{
			name:        "version with multiple dots in prerelease",
			version:     "1.0.0.alpha.beta.rc",
			shouldError: false, // should normalize to 1.0.0-alpha-beta-rc
		},
		{
			name:        "version already in correct format",
			version:     "1.0.0-alpha",
			shouldError: false,
		},
		{
			name:        "version with build metadata",
			version:     "1.0.0.alpha+build",
			shouldError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewVersion(test.version, SemanticFormat)
			if test.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSemanticConstraint_RubyNormalizerVsGemFormat(t *testing.T) {
	// Ensure that the ruby normalizer in semantic format doesn't conflict with gem format
	rubyStyleVersions := []string{
		"1.0.0.alpha",
		"1.0.0.beta.1",
		"1.0.0.rc2",
	}

	for _, version := range rubyStyleVersions {
		t.Run(version, func(t *testing.T) {
			// Both semantic and gem formats should be able to handle these versions
			semanticVer, semanticErr := NewVersion(version, SemanticFormat)
			gemVer, gemErr := NewVersion(version, GemFormat)

			// Both should succeed
			assert.NoError(t, semanticErr)
			assert.NoError(t, gemErr)

			// They might have different comparison behavior, but both should be valid
			assert.NotNil(t, semanticVer)
			assert.NotNil(t, gemVer)
		})
	}
}
