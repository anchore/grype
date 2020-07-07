package version

import (
	"errors"
	"testing"
)

func TestVersionSemantic(t *testing.T) {
	tests := []testCase{
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
