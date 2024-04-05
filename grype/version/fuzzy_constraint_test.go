package version

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSmartVerCmp(t *testing.T) {
	cases := []struct {
		v1, v2 string
		ret    int
	}{
		// Python PEP440 craziness
		{"1.5+1", "1.5+1.git.abc123de", -1},
		{"1.0.0-post1", "1.0.0-post2", -1},
		{"1.0.0", "1.0.0-post1", -1},
		{"1.0.0-dev1", "1.0.0-post1", -1},
		{"1.0.0-dev2", "1.0.0-post1", -1},
		{"1.0.0", "1.0.0-dev1", -1},
		{"5", "8", -1},
		{"15", "3", 1},
		{"4a", "4c", -1},
		{"1.0", "1.0", 0},
		{"1.0.1", "1.0", 1},
		{"1.0.14", "1.0.4", 1},
		{"95SE", "98SP1", -1},
		{"98SE", "98SP1", -1},
		{"98SP1", "98SP3", -1},
		{"16.0.0", "3.2.7", 1},
		{"10.23", "10.21", 1},
		{"64.0", "3.6.24", 1},
		{"5-1.15", "5-1.16", -1},
		{"5-1.15.2", "5-1.16", -1},
		{"5-appl_1.16.1", "5-1.0.1", -1}, // this is wrong, but seems to be impossible to account for
		{"5-1.16", "5_1.0.6", 1},
		{"5-6", "5-16", -1},
		{"5a1", "5a2", -1},
		{"5a1", "6a1", -1},
		{"5-a1", "5a1", -1}, // meh, kind of makes sense
		{"5-a1", "5.a1", 0},
		{"1.4", "1.02", 1},
		{"5.0", "08.0", -1},
		{"10.0", "1.0", 1},
		{"10.0", "1.000", 1},
		{"10.0", "1.000.0.1", 1},
		{"1.0.4", "1.0.4+metadata", -1}, // this is also somewhat wrong, however, there is a semver parser that can handle this case (which should be leveraged when possible)
		{"1.3.2-r0", "1.3.3-r0", -1},    // regression: regression for https://github.com/anchore/go-version/pull/2
		// Java JRE/JDK versioning prior to the implementing https://openjdk.org/jeps/223 for >= version 9
		{"1.8.0_456", "1.8.0", 1},
		{"1.8.0_456", "1.8.0_234", 1},
		{"1.8.0_456", "1.8.0_457", -1},
		{"1.8.0_456-b1", "1.8.0_456-b2", -1},
		{"1.8.0_456", "1.8.0_456-b1", -1},
		// Also check the semver equivalents of pre java version 9 work as expected:
		{"8.0.456", "8.0", 1},
		{"8.0.456", "8.0.234", 1},
		{"8.0.456", "8.0.457", -1},
		{"8.0.456+1", "8.0.456+2", -1},
		{"8.0.456", "8.0.456+1", -1},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q vs %q", c.v1, c.v2), func(t *testing.T) {
			if ret := fuzzyVersionComparison(c.v1, c.v2); ret != c.ret {
				t.Fatalf("expected %d, got %d", c.ret, ret)
			}
		})
	}
}

func TestFuzzyConstraintSatisfaction(t *testing.T) {
	tests := []testCase{
		{
			name:       "empty constraint",
			version:    "2.3.1",
			constraint: "",
			satisfied:  true,
		},
		{
			name:       "version range within",
			constraint: ">1.0, <2.0",
			version:    "1.2+beta-3",
			satisfied:  true,
		},
		{
			name:       "version within compound range",
			constraint: ">1.0, <2.0 || > 3.0",
			version:    "3.2+beta-3",
			satisfied:  true,
		},
		{
			name:       "version within compound range (2)",
			constraint: ">1.0, <2.0 || > 3.0",
			version:    "1.2+beta-3",
			satisfied:  true,
		},
		{
			name:       "version not within compound range",
			constraint: ">1.0, <2.0 || > 3.0",
			version:    "2.2+beta-3",
			satisfied:  false,
		},
		{
			name:       "version range within (prerelease)",
			constraint: ">1.0, <2.0",
			version:    "1.2.0-beta-prerelease",
			satisfied:  true,
		},
		{
			name:       "version range within (prerelease)",
			constraint: ">=1.0, <2.0",
			version:    "1.0.0-beta-prerelease",
			satisfied:  false,
		},
		{
			name:       "version range outside (right)",
			constraint: ">1.0, <2.0",
			version:    "2.1-beta-3",
			satisfied:  false,
		},
		{
			name:       "version range outside (left)",
			constraint: ">1.0, <2.0",
			version:    "0.9-beta-2",
			satisfied:  false,
		},
		{
			name:       "version range within (excluding left, prerelease)",
			constraint: ">=1.0, <2.0",
			version:    "1.0-beta-3",
			satisfied:  false,
		},
		{
			name:       "version range within (including left)",
			constraint: ">=1.1, <2.0",
			version:    "1.1",
			satisfied:  true,
		},
		{
			name:       "version range within (excluding right, 1)",
			constraint: ">1.0, <=2.0",
			version:    "2.0-beta-3",
			satisfied:  true,
		},
		{
			name:       "version range within (excluding right, 2)",
			constraint: ">1.0, <2.0",
			version:    "2.0-beta-3",
			satisfied:  true,
		},
		{
			name:       "version range within (including right)",
			constraint: ">1.0, <=2.0",
			version:    "2.0",
			satisfied:  true,
		},
		{
			name:       "version range within (including right, longer version [valid semver, bad fuzzy])",
			constraint: ">1.0, <=2.0",
			version:    "2.0.0",
			satisfied:  true,
		},
		{
			name:       "version range not within range (prefix)",
			constraint: ">1.0, <2.0",
			version:    "5-1.2+beta-3",
			satisfied:  false,
		},
		{
			name:       "odd major prefix wide constraint range",
			constraint: ">4, <6",
			version:    "5-1.2+beta-3",
			satisfied:  true,
		},
		{
			name:       "odd major prefix narrow constraint",
			constraint: ">5-1.15",
			version:    "5-1.16",
			satisfied:  true,
		},
		{
			name:       "odd major prefix narrow constraint range",
			constraint: ">5-1.15, <=5-1.16",
			version:    "5-1.16",
			satisfied:  true,
		},
		{
			name:       "odd major prefix narrow constraint range (excluding)",
			constraint: ">4, <5-1.16",
			version:    "5-1.16",
			satisfied:  false,
		},
		{
			name:       "bad semver (eq)",
			version:    "5a2",
			constraint: "=5a2",
			satisfied:  true,
		},
		{
			name:       "bad semver (gt)",
			version:    "5a2",
			constraint: ">5a1",
			satisfied:  true,
		},
		{
			name:       "bad semver (lt)",
			version:    "5a2",
			constraint: "<6a1",
			satisfied:  true,
		},
		{
			name:       "bad semver (lte)",
			version:    "5a2",
			constraint: "<=5a2",
			satisfied:  true,
		},
		{
			name:       "bad semver (gte)",
			version:    "5a2",
			constraint: ">=5a2",
			satisfied:  true,
		},
		{
			name:       "bad semver (lt boundary)",
			version:    "5a2",
			constraint: "<5a2",
			satisfied:  false,
		},
		// regression for https://github.com/anchore/go-version/pull/2
		{
			name:       "indirect package match",
			version:    "1.3.2-r0",
			constraint: "<= 1.3.3-r0",
			satisfied:  true,
		},
		{
			name:       "indirect package no match",
			version:    "1.3.4-r0",
			constraint: "<= 1.3.3-r0",
			satisfied:  false,
		},
		{
			name:       "vulndb fuzzy constraint single quoted",
			version:    "4.5.2",
			constraint: "'4.5.1' || '4.5.2'",
			satisfied:  true,
		},
		{
			name:       "vulndb fuzzy constraint double quoted",
			version:    "4.5.2",
			constraint: "\"4.5.1\" || \"4.5.2\"",
			satisfied:  true,
		},
		{
			name:       "strip unbalanced v from left side <",
			version:    "v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible",
			constraint: "< 1.5",
			satisfied:  false,
		},
		{
			name:       "strip unbalanced v from left side >",
			version:    "v17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible",
			constraint: "> 1.5",
			satisfied:  true,
		},
		{
			name:       "strip unbalanced v from right side <",
			version:    "17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible",
			constraint: "< v1.5",
			satisfied:  false,
		},
		{
			name:       "strip unbalanced v from right side >",
			version:    "17.12.0-ce-rc1.0.20200309214505-aa6a9891b09c+incompatible",
			constraint: "> v1.5",
			satisfied:  true,
		},
		{
			name:       "rc candidates with no '-' can match semver pattern",
			version:    "1.20rc1",
			constraint: " = 1.20.0-rc1",
			satisfied:  true,
		},
		{
			name:       "candidates ahead of alpha",
			version:    "3.11.0",
			constraint: "> 3.11.0-alpha1",
			satisfied:  true,
		},
		{
			name:       "candidates ahead of beta",
			version:    "3.11.0",
			constraint: "> 3.11.0-beta1",
			satisfied:  true,
		},
		{
			name:       "candidates ahead of same alpha versions",
			version:    "3.11.0-alpha5",
			constraint: "> 3.11.0-alpha1",
			satisfied:  true,
		},
		{
			name:       "candidates are placed correctly between alpha and release",
			version:    "3.11.0-beta5",
			constraint: "3.11.0 || = 3.11.0-alpha1",
			satisfied:  false,
		},
		{
			name:       "candidates with letter suffix are alphabetically greater than their versions",
			version:    "1.0.2a",
			constraint: " < 1.0.2w",
			satisfied:  true,
		},
		{
			name:       "candidates with multiple letter suffix are alphabetically greater than their versions",
			version:    "1.0.2zg",
			constraint: " < 1.0.2zh",
			satisfied:  true,
		},
		{
			name:       "candidates with pre suffix are sorted numerically",
			version:    "1.0.2pre1",
			constraint: " < 1.0.2pre2",
			satisfied:  true,
		},
		{
			name:       "candidates with letter suffix and r0 are alphabetically greater than their versions",
			version:    "1.0.2k-r0",
			constraint: " < 1.0.2l-r0",
			satisfied:  true,
		},
		{
			name:       "openssl version with letter suffix and r0 are alphabetically greater than their versions",
			version:    "1.0.2k-r0",
			constraint: ">= 1.0.2",
			satisfied:  true,
		},
		{
			name:       "openssl versions with letter suffix and r0 are alphabetically greater than their versions and compared equally to other lettered versions",
			version:    "1.0.2k-r0",
			constraint: ">= 1.0.2, < 1.0.2m",
			satisfied:  true,
		},
		{
			name:       "openssl pre2 is still considered less than release",
			version:    "1.1.1-pre2",
			constraint: "> 1.1.1-pre1, < 1.1.1",
			satisfied:  true,
		},
		{
			name:       "major version releases are less than their subsequent patch releases with letter suffixes",
			version:    "1.1.1",
			constraint: "> 1.1.1-a",
			satisfied:  true,
		},
		{
			name:       "go pseudoversion vulnerable: version is less, want less",
			version:    "0.0.0-20230716120725-531d2d74bc12",
			constraint: "<0.0.0-20230922105210-14b16010c2ee",
			satisfied:  true,
		},
		{
			name:       "go pseudoversion not vulnerable: same version but constraint is less",
			version:    "0.0.0-20230922105210-14b16010c2ee",
			constraint: "<0.0.0-20230922105210-14b16010c2ee",
			satisfied:  false,
		},
		{
			name:       "go pseudoversion not vulnerable: greater version",
			version:    "0.0.0-20230922112808-5421fefb8386",
			constraint: "<0.0.0-20230922105210-14b16010c2ee",
			satisfied:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constraint, err := newFuzzyConstraint(test.constraint, "")
			assert.NoError(t, err, "unexpected error from newFuzzyConstraint: %v", err)

			test.assertVersionConstraint(t, UnknownFormat, constraint)
		})
	}
}

func TestPseudoSemverPattern(t *testing.T) {
	tests := []struct {
		name    string
		version string
		valid   bool
	}{
		{name: "rc candidates are valid semver", version: "1.2.3-rc1", valid: true},
		{name: "rc candidates with no dash are valid semver", version: "1.2.3rc1", valid: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.valid, pseudoSemverPattern.MatchString(test.version))
		})
	}
}
