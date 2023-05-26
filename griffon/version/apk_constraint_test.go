package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionApk(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1", constraint: "", satisfied: true},
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
		// alpine specific scenarios
		// https://wiki.alpinelinux.org/wiki/APKBUILD_Reference#pkgver
		{version: "1.5.1-r1", constraint: "< 1.5.1", satisfied: false},
		{version: "1.5.1-r1", constraint: "> 1.5.1", satisfied: true},
		{version: "9.3.2-r4", constraint: "< 9.3.4-r2", satisfied: true},
		{version: "9.3.4-r2", constraint: "> 9.3.4", satisfied: true},
		{version: "4.2.52_p2-r1", constraint: "< 4.2.52_p4-r2", satisfied: true},
		{version: "4.2.52_p2-r1", constraint: "> 4.2.52_p4-r2", satisfied: false},
		{version: "0.1.0_alpha", constraint: "< 0.1.3_alpha", satisfied: true},
		{version: "0.1.0_alpha2", constraint: "> 0.1.0_alpha", satisfied: true},
		{version: "1.1", constraint: "> 1.1_alpha1", satisfied: true},
		{version: "1.1", constraint: "< 1.1_alpha1", satisfied: false},
		{version: "2.3.0b-r1", constraint: "< 2.3.0b-r2", satisfied: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newApkConstraint(test.constraint)

			assert.NoError(t, err, "unexpected error from newApkConstraint: %v", err)
			test.assertVersionConstraint(t, ApkFormat, constraint)

		})
	}
}
