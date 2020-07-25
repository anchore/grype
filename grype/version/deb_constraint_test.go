package version

import (
	"errors"
	"testing"
)

func TestVersionDeb(t *testing.T) {
	tests := []testCase{
		// compound conditions
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
		// fixed-in scenarios
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
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0.0", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.1", satisfied: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.2", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.4", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0", satisfied: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0.0", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11-2ubuntu0.14.04.1", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.7", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u150", satisfied: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152-2.6.11-2ubuntu0.14.04.1", satisfied: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 8u1-2.6.11-2ubuntu0.14.04.1", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81-0ubuntu0.14.04.1.1089", satisfied: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.82-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2358-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.1-0ubuntu0.14.04.1.1089", satisfied: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<44-0ubuntu0.14.04.1.1089", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.name(), func(t *testing.T) {
			constraint, err := newDebConstraint(test.constraint)
			if !errors.Is(err, test.constErr) {
				t.Fatalf("unexpected constraint error: '%+v'!='%+v'", err, test.constErr)
			}

			test.assert(t, DebFormat, constraint)
		})
	}
}
