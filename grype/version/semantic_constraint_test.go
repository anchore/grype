package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionSemantic(t *testing.T) {
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
			constraint, err := newSemanticConstraint(test.constraint)
			assert.NoError(t, err, "unexpected error from newSemanticConstraint: %v", err)

			test.assertVersionConstraint(t, SemanticFormat, constraint)
		})
	}
}
