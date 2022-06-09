package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGemfileConstraint(t *testing.T) {
	tests := []testCase{
		// empty values
		{version: "2.3.1", constraint: "", satisfied: true},
		// typical cases
		{version: "0.9.9-r0", constraint: "< 0.9.12-r1", satisfied: true}, // regression case
		{version: "1.5.0-arm-windows", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.2.0-arm-windows", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "0.0.1-armv5-window", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.0.1-armv7-linux", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0-universal-darwin-9", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0-universal-darwin-10", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.6.0-x86_64-darwin-10", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.2.0", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86-linux", constraint: ">1.0, <2.0", satisfied: true},
		{version: "1.2.0-x86-linux", constraint: "= 1.2.0", satisfied: true},
		{version: "1.2.0-x86_64-linux", constraint: "= 1.2.0", satisfied: true},
		{version: "1.2.0-x86_64-linux", constraint: "< 1.2.1", satisfied: true},
		{version: "1.2.3----RC-SNAPSHOT.12.9.1--.12+788", constraint: "> 1.0.0", satisfied: true},
		{version: "1.2.3----RC-SNAPSHOT.12.9.1--.12+788-armv7-darwin", constraint: "< 1.2.3", satisfied: true},
		{version: "1.2.3----rc-snapshot.12.9.1--.12+788-armv7-darwin", constraint: "< 1.2.3", satisfied: true},
		// https://semver.org/#spec-item-11
		{version: "1.2.0-alpha-x86-linux", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1-x86-linux", constraint: "<1.2.0", satisfied: true},
		// gem versions seem to respect the order: {sem-version}+{meta}-{arch}-{os}
		// but let's check the extraction works even when the order of {meta}-{arch} varies.
		{version: "1.2.0-alpha-1-x86-linux+meta", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1+meta-x86-linux", constraint: "<1.2.0", satisfied: true},
		{version: "1.2.0-alpha-1-x86-linux+meta", constraint: ">1.1.0", satisfied: true},
		{version: "1.2.0-alpha-1-arm-linux+meta", constraint: ">1.1.0", satisfied: true},
		{version: "1.0.0-alpha-a.b-c-somethinglong+build.1-aef.1-its-okay", constraint: "<1.0.0", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.tName(), func(t *testing.T) {
			constraint, err := newSemanticConstraint(test.constraint)
			assert.NoError(t, err, "unexpected error from newSemanticConstraint: %v", err)

			test.assertVersionConstraint(t, GemfileFormat, constraint)
		})
	}

}
