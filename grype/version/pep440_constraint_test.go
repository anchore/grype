package version

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestItWorks(t *testing.T) {
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
			name:       "date based pep440 version string boundary condition",
			version:    "2022.12.7",
			constraint: ">=2017.11.05,<2022.12.07",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newPep440Constraint(tc.constraint)
			require.NoError(t, err)
		})
	}
}
