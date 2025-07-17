package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKbVersion_Constraint(t *testing.T) {
	tests := []testCase{
		{
			name:    "no constraint no version raises error",
			version: "", constraint: "",
			satisfied: false,
			wantError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				var expectedError *NonFatalConstraintError
				assert.ErrorAs(t, err, &expectedError, "Unexpected error type from kbConstraint.Satisfied: %v", err)
			},
		},
		{
			name:    "no constraint with version raises error",
			version: "878787", constraint: "",
			satisfied: false,
			wantError: func(t require.TestingT, err error, msgAndArgs ...interface{}) {
				var expectedError *NonFatalConstraintError
				assert.ErrorAs(t, err, &expectedError, "Unexpected error type from kbConstraint.Satisfied: %v", err)
			},
		},
		{name: "no version is unsatisfied", version: "", constraint: "foo", satisfied: false},
		{name: "version constraint mismatch", version: "1", constraint: "foo", satisfied: false},
		{name: "matching version and constraint", version: "1", constraint: "1", satisfied: true},
		{name: "base keyword matching version and constraint", version: "base", constraint: "base", satisfied: true},
		{name: "version and OR constraint match", version: "878787", constraint: "979797 || 101010 || 878787", satisfied: true},
		{name: "version and OR constraint mismatch", version: "478787", constraint: "979797 || 101010 || 878787", satisfied: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := GetConstraint(test.constraint, KBFormat)
			assert.NoError(t, err, "unexpected error from newKBConstraint: %v", err)

			test.assertVersionConstraint(t, KBFormat, constraint)
		})
	}
}
