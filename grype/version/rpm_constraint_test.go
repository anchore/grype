package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionRpmConstraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// trivial compound conditions
		{version: "2.3.1", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.3.1", constraint: "> 1.0.0, < 2.0.0", satisfied: true},
		{version: "2.0.0", constraint: "> 1.0.0, <= 2.0.0", satisfied: true},
		{version: "2.0.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.0.0", constraint: ">= 1.0.0, < 2.0.0", satisfied: true},
		{version: "1.0.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.9.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.2.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.0.1", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		// trivial scenarios
		{version: "2.3.1", constraint: "< 2.0.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2.0", satisfied: false},
		{version: "2.3.1", constraint: "< 2", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3.1", satisfied: false},
		{version: "2.3.1", constraint: "< 2.3.2", satisfied: true},
		{version: "2.3.1", constraint: "< 2.4", satisfied: true},
		{version: "2.3.1", constraint: "< 3", satisfied: true},
		{version: "2.3.1", constraint: "< 3.0", satisfied: true},
		{version: "2.3.1", constraint: "< 3.0.0", satisfied: true},
		// epoch
		{version: "1:0", constraint: "< 0:1", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "<= 2:4.19.1-1.el7_5", satisfied: true},
		{version: "0:4.19.1-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: true},
		{version: "11:4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: true},
		{version: "13:4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: false},
		// regression: https://github.com/anchore/grype/issues/316
		{version: "1.5.4-2.el7_9", constraint: "< 0:1.5.4-2.el7_9", satisfied: false},
		{version: "1.5.4-2.el7", constraint: "< 0:1.5.4-2.el7_9", satisfied: true},
		// Non-standard epoch handling. In comparisons with epoch on only one side, they are both ignored
		{version: "1:0", constraint: "< 1", satisfied: true},
		{version: "0:0", constraint: "< 0", satisfied: false},
		{version: "0:0", constraint: "= 0", satisfied: true},
		{version: "0", constraint: "= 0:0", satisfied: true},
		{version: "1.0", constraint: "< 2:1.0", satisfied: false},
		{version: "1.0", constraint: "<= 2:1.0", satisfied: true},
		{version: "1:2", constraint: "< 1", satisfied: false},
		{version: "1:2", constraint: "> 1", satisfied: true},
		{version: "2:4.19.01-1.el7_5", constraint: "< 4.19.1-1.el7_5", satisfied: false},
		{version: "2:4.19.01-1.el7_5", constraint: "<= 4.19.1-1.el7_5", satisfied: true},
		{version: "4.19.01-1.el7_5", constraint: "< 2:4.19.1-1.el7_5", satisfied: false},
		{version: "4.19.0-1.el7_5", constraint: "< 12:4.19.0-1.el7", satisfied: false},
		{version: "4.19.0-1.el7_5", constraint: "<= 12:4.19.0-1.el7", satisfied: false},
		{version: "3:4.19.0-1.el7_5", constraint: "< 4.21.0-1.el7", satisfied: true},
		{version: "4:1.2.3-3-el7_5", constraint: "< 1.2.3-el7_5~snapshot1", satisfied: false},
		// regression https://github.com/anchore/grype/issues/398
		{version: "8.3.1-5.el8.4", constraint: "< 0:8.3.1-5.el8.5", satisfied: true},
		{version: "8.3.1-5.el8.40", constraint: "< 0:8.3.1-5.el8.5", satisfied: false},
		{version: "8.3.1-5.el8", constraint: "< 0:8.3.1-5.el8.0.0", satisfied: false},
		{version: "8.3.1-5.el8", constraint: "<= 0:8.3.1-5.el8.0.0", satisfied: true},
		{version: "8.3.1-5.el8.0.0", constraint: "> 0:8.3.1-5.el8", satisfied: false},
		{version: "8.3.1-5.el8.0.0", constraint: ">= 0:8.3.1-5.el8", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := newRpmConstraint(test.constraint)
			assert.NoError(t, err, "unexpected error from newRpmConstraint: %v", err)

			test.assertVersionConstraint(t, RpmFormat, constraint)
		})
	}
}
