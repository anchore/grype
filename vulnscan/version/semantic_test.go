package version

import (
	"errors"
	"testing"
)

func TestVersionSemantic(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1", constraint: "2.3.1", isVulnerable: true},
		{version: "2.3.1", constraint: "= 2.3.1", isVulnerable: true},
		{version: "2.3.1", constraint: "  =   2.3.1", isVulnerable: true},
		{version: "2.3.1", constraint: ">= 2.3.1", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2.0.0", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2.0", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2, < 3", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2.3, < 3.1", isVulnerable: true},
		{version: "2.3.1", constraint: "> 2.3.0, < 3.1", isVulnerable: true},
		{version: "2.3.1", constraint: ">= 2.3.1, < 3.1", isVulnerable: true},
		{version: "2.3.1", constraint: "  =  2.3.2", isVulnerable: false},
		{version: "2.3.1", constraint: ">= 2.3.2", isVulnerable: false},
		{version: "2.3.1", constraint: "> 2.3.1", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.0.0", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.0", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2, > 3", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "2.3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "= 2.3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "  =   2.3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2.0.0", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2.0", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2, < 3", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2.3, < 3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "> 2.3.0, < 3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1, < 3.1", isVulnerable: true},
		{version: "2.3.1+meta", constraint: "  =  2.3.2", isVulnerable: false},
		{version: "2.3.1+meta", constraint: ">= 2.3.2", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "> 2.3.1", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "< 2.0.0", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "< 2.0", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "< 2", isVulnerable: false},
		{version: "2.3.1+meta", constraint: "< 2, > 3", isVulnerable: false},
		// from https://github.com/hashicorp/go-version/issues/61
		// and https://semver.org/#spec-item-11
		// A larger set of pre-release fields has a higher precedence than a smaller set, if all of the preceding identifiers are equal.
		{version: "1.0.0-alpha", constraint: "> 1.0.0-alpha.1", isVulnerable: false},
		{version: "1.0.0-alpha", constraint: "< 1.0.0-alpha.1", isVulnerable: true},
		{version: "1.0.0-alpha.1", constraint: "> 1.0.0-alpha.beta", isVulnerable: false},
		{version: "1.0.0-alpha.1", constraint: "< 1.0.0-alpha.beta", isVulnerable: true},
		{version: "1.0.0-alpha.beta", constraint: "> 1.0.0-beta", isVulnerable: false},
		{version: "1.0.0-alpha.beta", constraint: "< 1.0.0-beta", isVulnerable: true},
		{version: "1.0.0-beta", constraint: "> 1.0.0-beta.2", isVulnerable: false},
		{version: "1.0.0-beta", constraint: "< 1.0.0-beta.2", isVulnerable: true},
		{version: "1.0.0-beta.2", constraint: "> 1.0.0-beta.11", isVulnerable: false},
		{version: "1.0.0-beta.2", constraint: "< 1.0.0-beta.11", isVulnerable: true},
		{version: "1.0.0-beta.11", constraint: "> 1.0.0-rc.1", isVulnerable: false},
		{version: "1.0.0-beta.11", constraint: "< 1.0.0-rc.1", isVulnerable: true},
		{version: "1.0.0-rc.1", constraint: "> 1.0.0", isVulnerable: false},
		{version: "1.0.0-rc.1", constraint: "< 1.0.0", isVulnerable: true},
		{version: "1.0.0-alpha.1", constraint: "> 1.0.0-alpha.1", isVulnerable: false},
		{version: "1.0.0-alpha.2", constraint: "> 1.0.0-alpha.1", isVulnerable: true},
		{version: "1.2.0-beta", constraint: ">1.0, <2.0", isVulnerable: true},
		{version: "1.2.0-beta", constraint: ">1.0", isVulnerable: true},
		{version: "1.2.0-beta", constraint: "<2.0", isVulnerable: true},
		{version: "1.2.0", constraint: ">1.0, <2.0", isVulnerable: true},
	}

	for _, test := range tests {
		t.Run(test.name(), func(t *testing.T) {
			constraint, err := newSemanticConstraint(test.constraint)
			if !errors.Is(err, test.constErr) {
				t.Fatalf("unexpected constraint error: '%+v'!='%+v'", err, test.constErr)
			}

			test.assert(t, SemanticFormat, constraint)
		})
	}
}
