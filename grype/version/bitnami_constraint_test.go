package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionBitnami(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// typical cases
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
		{version: "2.3.1-1", constraint: "2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "= 2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "  =   2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: ">= 2.3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.0.0", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.0", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2, < 3", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.3, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "> 2.3.0, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: ">= 2.3.1, < 3.1", satisfied: true},
		{version: "2.3.1-1", constraint: "  =  2.3.2", satisfied: false},
		{version: "2.3.1-1", constraint: ">= 2.3.2", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2, > 3", satisfied: false},
		// Ignoring revisions
		{version: "2.3.1-1", constraint: "> 2.3.1", satisfied: false},
		{version: "2.3.1-1", constraint: "< 2.3.1-2", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// We use newSemanticConstraint but using BitnamiFormat as the format
			constraint, err := newSemanticConstraint(test.constraint)

			assert.NoError(t, err, "unexpected error from newSemanticConstraint: %v", err)
			test.assertVersionConstraint(t, BitnamiFormat, constraint)
		})
	}
}
