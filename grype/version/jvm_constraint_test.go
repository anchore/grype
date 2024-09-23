package version

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionConstraintJVM(t *testing.T) {
	tests := []testCase{
		// pre jep 223 versions
		{version: "1.7.0_80", constraint: "< 1.8.0", satisfied: true},
		{version: "1.8.0_131", constraint: "> 1.8.0", satisfied: true},
		{version: "1.8.0_131", constraint: "< 1.8.0_132", satisfied: true},
		{version: "1.8.0_131-b11", constraint: "< 1.8.0_132", satisfied: true},

		{version: "1.7.0_80", constraint: "> 1.8.0", satisfied: false},
		{version: "1.8.0_131", constraint: "< 1.8.0", satisfied: false},
		{version: "1.8.0_131", constraint: "> 1.8.0_132", satisfied: false},
		{version: "1.8.0_131-b11", constraint: "> 1.8.0_132", satisfied: false},

		{version: "1.7.0_80", constraint: "= 1.8.0", satisfied: false},
		{version: "1.8.0_131", constraint: "= 1.8.0", satisfied: false},
		{version: "1.8.0_131", constraint: "= 1.8.0_132", satisfied: false},
		{version: "1.8.0_131-b11", constraint: "= 1.8.0_132", satisfied: false},

		{version: "1.8.0_80", constraint: "= 1.8.0_80", satisfied: true},
		{version: "1.8.0_131", constraint: ">= 1.8.0_131", satisfied: true},
		{version: "1.8.0_131", constraint: "= 1.8.0_131-b001", satisfied: true}, // builds should not matter
		{version: "1.8.0_131-ea-b11", constraint: "= 1.8.0_131-ea", satisfied: true},

		// jep 223 versions
		{version: "8.0.4", constraint: "> 8.0.3", satisfied: true},
		{version: "8.0.4", constraint: "< 8.0.5", satisfied: true},
		{version: "9.0.0", constraint: "> 8.0.5", satisfied: true},
		{version: "9.0.0", constraint: "< 9.1.0", satisfied: true},
		{version: "11.0.4", constraint: "<= 11.0.4", satisfied: true},
		{version: "11.0.5", constraint: "> 11.0.4", satisfied: true},

		{version: "8.0.4", constraint: "< 8.0.3", satisfied: false},
		{version: "8.0.4", constraint: "> 8.0.5", satisfied: false},
		{version: "9.0.0", constraint: "< 8.0.5", satisfied: false},
		{version: "9.0.0", constraint: "> 9.1.0", satisfied: false},
		{version: "11.0.4", constraint: "> 11.0.4", satisfied: false},
		{version: "11.0.5", constraint: "< 11.0.4", satisfied: false},

		// mixed versions
		{version: "1.8.0_131", constraint: "< 9.0.0", satisfied: true}, // 1.8.0_131 -> 8.0.131
		{version: "9.0.0", constraint: "> 1.8.0_131", satisfied: true}, // 1.8.0_131 -> 8.0.131
		{version: "1.8.0_131", constraint: "<= 8.0.131", satisfied: true},
		{version: "1.8.0_131", constraint: "> 7.0.79", satisfied: true},
		{version: "1.8.0_131", constraint: "= 8.0.131", satisfied: true},
		{version: "1.8.0_131", constraint: ">= 9.0.0", satisfied: false},
		{version: "9.0.1", constraint: "< 8.0.131", satisfied: false},

		// pre-release versions
		{version: "1.8.0_131-ea", constraint: "< 1.8.0_131", satisfied: true},
		{version: "1.8.0_131", constraint: "> 1.8.0_131-ea", satisfied: true},
		{version: "9.0.0-ea", constraint: "< 9.0.0", satisfied: true},
		{version: "9.0.0-ea", constraint: "> 1.8.0_131", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.version+"_constraint_"+test.constraint, func(t *testing.T) {
			constraint, err := newJvmConstraint(test.constraint)
			require.NoError(t, err)
			test.assertVersionConstraint(t, JVMFormat, constraint)
		})
	}
}
