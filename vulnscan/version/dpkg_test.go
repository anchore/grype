package version

import (
	"errors"
	"testing"
)

func TestVersionDpkg(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1", constraint: "< 2.0.0", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.0", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.3", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.3.1", isVulnerable: false},
		{version: "2.3.1", constraint: "< 2.3.2", isVulnerable: true},
		{version: "2.3.1", constraint: "< 2.4", isVulnerable: true},
		{version: "2.3.1", constraint: "< 3", isVulnerable: true},
		{version: "2.3.1", constraint: "< 3.0", isVulnerable: true},
		{version: "2.3.1", constraint: "< 3.0.0", isVulnerable: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0.0", isVulnerable: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.0", isVulnerable: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2", isVulnerable: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3", isVulnerable: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.1", isVulnerable: false},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.3.2", isVulnerable: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <2.4", isVulnerable: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3", isVulnerable: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0", isVulnerable: true},
		{version: "2.3.1-1ubuntu0.14.04.1", constraint: " <3.0.0", isVulnerable: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11-2ubuntu0.14.04.1", isVulnerable: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.6.11", isVulnerable: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151-2.7", isVulnerable: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u151", isVulnerable: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u150", isVulnerable: false},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152", isVulnerable: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 7u152-2.6.11-2ubuntu0.14.04.1", isVulnerable: true},
		{version: "7u151-2.6.11-2ubuntu0.14.04.1", constraint: " < 8u1-2.6.11-2ubuntu0.14.04.1", isVulnerable: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43", isVulnerable: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0", isVulnerable: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357", isVulnerable: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81", isVulnerable: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.81-0ubuntu0.14.04.1.1089", isVulnerable: false},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2357.82-0ubuntu0.14.04.1.1089", isVulnerable: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.0.2358-0ubuntu0.14.04.1.1089", isVulnerable: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<43.1-0ubuntu0.14.04.1.1089", isVulnerable: true},
		{version: "43.0.2357.81-0ubuntu0.14.04.1.1089", constraint: "<44-0ubuntu0.14.04.1.1089", isVulnerable: true},
	}

	for _, test := range tests {
		t.Run(test.name(), func(t *testing.T) {
			constraint, err := newDpkgConstraint(test.constraint)
			if !errors.Is(err, test.constErr) {
				t.Fatalf("unexpected constraint error: '%+v'!='%+v'", err, test.constErr)
			}

			test.assert(t, DpkgFormat, constraint)
		})
	}
}
