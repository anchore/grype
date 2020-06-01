package version

import (
	"errors"
	"testing"
)

func TestVersionSemantic_Basic(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1", constraint: "2.3.1", expected: true},
		{version: "2.3.1", constraint: "= 2.3.1", expected: true},
		{version: "2.3.1", constraint: "  =   2.3.1", expected: true},
		{version: "2.3.1", constraint: ">= 2.3.1", expected: true},
		{version: "2.3.1", constraint: "> 2.0.0", expected: true},
		{version: "2.3.1", constraint: "> 2.0", expected: true},
		{version: "2.3.1", constraint: "> 2", expected: true},
		{version: "2.3.1", constraint: "> 2, < 3", expected: true},
		{version: "2.3.1", constraint: "> 2.3, < 3.1", expected: true},
		{version: "2.3.1", constraint: "> 2.3.0, < 3.1", expected: true},
		{version: "2.3.1", constraint: ">= 2.3.1, < 3.1", expected: true},
		{version: "2.3.1", constraint: "  =  2.3.2", expected: false},
		{version: "2.3.1", constraint: ">= 2.3.2", expected: false},
		{version: "2.3.1", constraint: "> 2.3.1", expected: false},
		{version: "2.3.1", constraint: "< 2.0.0", expected: false},
		{version: "2.3.1", constraint: "< 2.0", expected: false},
		{version: "2.3.1", constraint: "< 2", expected: false},
		{version: "2.3.1", constraint: "< 2, > 3", expected: false},
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

func TestVersionSemantic_Metadata(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1+meta", constraint: "2.3.1", expected: true},
		{version: "2.3.1+meta", constraint: "= 2.3.1", expected: true},
		{version: "2.3.1+meta", constraint: "  =   2.3.1", expected: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1", expected: true},
		{version: "2.3.1+meta", constraint: "> 2.0.0", expected: true},
		{version: "2.3.1+meta", constraint: "> 2.0", expected: true},
		{version: "2.3.1+meta", constraint: "> 2", expected: true},
		{version: "2.3.1+meta", constraint: "> 2, < 3", expected: true},
		{version: "2.3.1+meta", constraint: "> 2.3, < 3.1", expected: true},
		{version: "2.3.1+meta", constraint: "> 2.3.0, < 3.1", expected: true},
		{version: "2.3.1+meta", constraint: ">= 2.3.1, < 3.1", expected: true},
		{version: "2.3.1+meta", constraint: "  =  2.3.2", expected: false},
		{version: "2.3.1+meta", constraint: ">= 2.3.2", expected: false},
		{version: "2.3.1+meta", constraint: "> 2.3.1", expected: false},
		{version: "2.3.1+meta", constraint: "< 2.0.0", expected: false},
		{version: "2.3.1+meta", constraint: "< 2.0", expected: false},
		{version: "2.3.1+meta", constraint: "< 2", expected: false},
		{version: "2.3.1+meta", constraint: "< 2, > 3", expected: false},
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
