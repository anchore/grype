package version

import (
	"errors"
	"testing"
)

func TestVersionCpe23(t *testing.T) {
	tests := []testCase{
		{version: "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", constraint: "cpe:2.3:a:vendor:product:version:update:edition:language:softwareedition:targetsw:targethw:other", isVulnerable: false},
		{version: "cpe:2.3:a:foobar:*:*:*:*:*:*:*:*:*", constraint: "cpe:2.3:a:vendor:product:version:update:edition:language:softwareedition:targetsw:targethw:other", isVulnerable: false},
		{version: "cpe:2.3:a:foobar:producta:1.0.0:*:*:*:*:*:*:*", constraint: ">= cpe:2.3:a:foobar:producta:1.0.0:*:*:*:*:*:*:*, <= cpe:2.3:a:foobar:producta:1.0.1:*:*:*:*:*:*:*", isVulnerable: true},
	}

	for _, test := range tests {
		t.Run(test.name(), func(t *testing.T) {
			constraint, err := newCpeConstraint(test.constraint)
			if !errors.Is(err, test.constErr) {
				t.Fatalf("unexpected constraint error: '%+v'!='%+v'", err, test.constErr)
			}

			test.assert(t, Cpe23Format, constraint)
		})
	}
}
