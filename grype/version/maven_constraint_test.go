package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionConstraintJava(t *testing.T) {
	tests := []testCase{
		{version: "1", constraint: "< 2.5", satisfied: true},
		{version: "1.0", constraint: "< 1.1", satisfied: true},
		{version: "1.1", constraint: "< 1.2", satisfied: true},
		{version: "1.0.0", constraint: "< 1.1", satisfied: true},
		{version: "1.0.1", constraint: "< 1.1", satisfied: true},
		{version: "1.1", constraint: "> 1.2.0", satisfied: false},
		{version: "1.0-alpha-1", constraint: "> 1.0", satisfied: false},
		{version: "1.0-alpha-1", constraint: "> 1.0-alpha-2", satisfied: false},
		{version: "1.0-alpha-1", constraint: "< 1.0-beta-1", satisfied: true},
		{version: "1.0-beta-1", constraint: "< 1.0-SNAPSHOT", satisfied: true},
		{version: "1.0-SNAPSHOT", constraint: "< 1.0", satisfied: true},
		{version: "1.0-alpha-1-SNAPSHOT", constraint: "> 1.0-alpha-1", satisfied: false},
		{version: "1.0", constraint: "< 1.0-1", satisfied: true},
		{version: "1.0-1", constraint: "< 1.0-2", satisfied: true},
		{version: "1.0.0", constraint: "< 1.0-1", satisfied: true},
		{version: "2.0-1", constraint: "> 2.0.1", satisfied: false},
		{version: "2.0.1-klm", constraint: "> 2.0.1-lmn", satisfied: false},
		{version: "2.0.1", constraint: "< 2.0.1-xyz", satisfied: true},
		{version: "2.0.1", constraint: "< 2.0.1-123", satisfied: true},
		{version: "2.0.1-xyz", constraint: "< 2.0.1-123", satisfied: true},
		{version: "2.414.2-cb-5", constraint: "> 2.414.2", satisfied: true},
		{version: "5.2.25.RELEASE", constraint: "< 5.2.25", satisfied: false},
		{version: "5.2.25.RELEASE", constraint: "<= 5.2.25", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newMavenConstraint(test.constraint)

			assert.NoError(t, err, "unexpected error from newMavenConstraint %s: %v", test.version, err)
			test.assertVersionConstraint(t, MavenFormat, constraint)

		})
	}
}

func TestVersionEqualityJava(t *testing.T) {
	tests := []testCase{
		{version: "1", constraint: "1", satisfied: true},
		{version: "1", constraint: "1.0", satisfied: true},
		{version: "1", constraint: "1.0.0", satisfied: true},
		{version: "1.0", constraint: "1.0.0", satisfied: true},
		{version: "1", constraint: "1-0", satisfied: true},
		{version: "1", constraint: "1.0-0", satisfied: true},
		{version: "1.0", constraint: "1.0-0", satisfied: true},
		{version: "1a", constraint: "1-a", satisfied: true},
		{version: "1a", constraint: "1.0-a", satisfied: true},
		{version: "1a", constraint: "1.0.0-a", satisfied: true},
		{version: "1.0a", constraint: "1-a", satisfied: true},
		{version: "1.0.0a", constraint: "1-a", satisfied: true},
		{version: "1x", constraint: "1-x", satisfied: true},
		{version: "1x", constraint: "1.0-x", satisfied: true},
		{version: "1x", constraint: "1.0.0-x", satisfied: true},
		{version: "1.0x", constraint: "1-x", satisfied: true},
		{version: "1.0.0x", constraint: "1-x", satisfied: true},
		{version: "1ga", constraint: "1", satisfied: true},
		{version: "1release", constraint: "1", satisfied: true},
		{version: "1final", constraint: "1", satisfied: true},
		{version: "1cr", constraint: "1rc", satisfied: true},
		{version: "1a1", constraint: "1-alpha-1", satisfied: true},
		{version: "1b2", constraint: "1-beta-2", satisfied: true},
		{version: "1m3", constraint: "1-milestone-3", satisfied: true},
		{version: "1X", constraint: "1x", satisfied: true},
		{version: "1A", constraint: "1a", satisfied: true},
		{version: "1B", constraint: "1b", satisfied: true},
		{version: "1M", constraint: "1m", satisfied: true},
		{version: "1Ga", constraint: "1", satisfied: true},
		{version: "1GA", constraint: "1", satisfied: true},
		{version: "1RELEASE", constraint: "1", satisfied: true},
		{version: "1release", constraint: "1", satisfied: true},
		{version: "1RELeaSE", constraint: "1", satisfied: true},
		{version: "1Final", constraint: "1", satisfied: true},
		{version: "1FinaL", constraint: "1", satisfied: true},
		{version: "1FINAL", constraint: "1", satisfied: true},
		{version: "1Cr", constraint: "1Rc", satisfied: true},
		{version: "1cR", constraint: "1rC", satisfied: true},
		{version: "1m3", constraint: "1Milestone3", satisfied: true},
		{version: "1m3", constraint: "1MileStone3", satisfied: true},
		{version: "1m3", constraint: "1MILESTONE3", satisfied: true},
		{version: "1", constraint: "01", satisfied: true},
		{version: "1", constraint: "001", satisfied: true},
		{version: "1.1", constraint: "1.01", satisfied: true},
		{version: "1.1", constraint: "1.001", satisfied: true},
		{version: "1-1", constraint: "1-01", satisfied: true},
		{version: "1-1", constraint: "1-001", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newMavenConstraint(test.constraint)

			assert.NoError(t, err, "unexpected error from newMavenConstraint %s: %v", test.version, err)
			test.assertVersionConstraint(t, MavenFormat, constraint)
		})
	}
}
