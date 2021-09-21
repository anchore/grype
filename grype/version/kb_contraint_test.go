package version

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVersionKbConstraint(t *testing.T) {
	tests := []testCase{
		{testName: "no constraint no version raises error", version: "", constraint: "", satisfied: false, shouldErr: true, errorAssertion: func(t *testing.T, err error) {
			var expectedError *NonFatalConstraintError
			assert.ErrorAs(t, err, &expectedError, "Unexpected error type from kbConstraint.Satisfied: %v", err)
		}},
		{testName: "no constraint with version raises error", version: "878787", constraint: "", satisfied: false, shouldErr: true, errorAssertion: func(t *testing.T, err error) {
			var expectedError *NonFatalConstraintError
			assert.ErrorAs(t, err, &expectedError, "Unexpected error type from kbConstraint.Satisfied: %v", err)
		}},
		{testName: "no version is unsatisifed", version: "", constraint: "foo", satisfied: false},
		{testName: "version constraint mismatch", version: "1", constraint: "foo", satisfied: false},
		{testName: "matching version and constraint", version: "1", constraint: "1", satisfied: true},
		{testName: "base keyword matching version and constraint", version: "base", constraint: "base", satisfied: true},
		{testName: "version and OR constraint match", version: "878787", constraint: "979797 || 101010 || 878787", satisfied: true},
		{testName: "version and OR constraint mismatch", version: "478787", constraint: "979797 || 101010 || 878787", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.name(), func(t *testing.T) {
			constraint, err := newKBConstraint(test.constraint)
			assert.NoError(t, err, "unexpected error from newKBConstraint: %v", err)

			test.assertVersionConstraint(t, KBFormat, constraint)
		})
	}
}
