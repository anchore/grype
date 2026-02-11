package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPep440Version_Constraint(t *testing.T) {
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
			name:       "candidates with pre suffix are sorted numerically",
			version:    "1.0.2pre1",
			constraint: " < 1.0.2pre2",
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
		{
			name:       "certifi false positive is fixed",
			version:    "2022.12.7",
			constraint: ">=2017.11.05,<2022.12.07",
		},
		// regression (partial version with metadata should be valid)
		// this is a fun one! PEP 440 has two different use cases for ordering semantics: direct versions and version specifiers.
		// Take this python code for example:
		//
		// ```python
		// from packaging.version import Version
		// from packaging.specifiers import SpecifierSet
		//
		// # direct ordering comparison
		// Version('6.4+cgr.1') <= Version('6.4.0')  # False
		//
		// # specifier matching
		// Version('6.4+cgr.1') in SpecifierSet('<=6.4.0')  # True
		// ```
		//
		// The root cause of the regression is that we have been doing direct version comparisons instead of specifier matching.
		// The fix is to treat constraint matching as specifier matching (only consider the public version segment for
		// constraint matching, not the local version segment).
		//
		// We want specifier semantics (ignore local) since 6.4+cgr.1 should be considered "the same release" as
		// 6.4 for vulnerability matching applicability.
		{
			name:       "partial version with metadata",
			version:    "6.4+cgr.1",
			constraint: "<=6.4.0",
			satisfied:  true,
		},
		// When constraint has a local version, require exact match (important for unaffected entries)
		{
			name:       "local version in constraint should not match version without local segment",
			version:    "2.0.0",
			constraint: "= 2.0.0+cgr.1",
			satisfied:  false,
		},
		{
			name:       "local version in constraint should match same local version",
			version:    "2.0.0+cgr.1",
			constraint: "= 2.0.0+cgr.1",
			satisfied:  true,
		},
		{
			name:       "version with local segment should match constraint without local segment",
			version:    "2.0.0+cgr.1",
			constraint: "= 2.0.0",
			satisfied:  true,
		},
		{
			name:       "version with local segment should satisfy less-than constraint",
			version:    "2.0.0+cgr.1",
			constraint: "< 2.0.1",
			satisfied:  true,
		},
		{
			name:       "different local versions should not match on equality",
			version:    "2.0.0+other",
			constraint: "= 2.0.0+cgr.1",
			satisfied:  false,
		},
		// Local version segments compared per PEP 440 (numeric segments as integers)
		{
			name:       "local version segments compared numerically not lexicographically",
			version:    "2.0.0+cgr.12",
			constraint: "> 2.0.0+cgr.2",
			satisfied:  true,
		},
		{
			name:       "local version segment numeric comparison - less than",
			version:    "2.0.0+cgr.2",
			constraint: "< 2.0.0+cgr.12",
			satisfied:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := GetConstraint(tc.constraint, PythonFormat)
			require.NoError(t, err)
			v := New(tc.version, PythonFormat)
			sat, err := c.Satisfied(v)
			require.NoError(t, err)
			assert.Equal(t, tc.satisfied, sat)
		})
	}
}

func TestPep440Version_Compare(t *testing.T) {
	tests := []struct {
		name           string
		thisVersion    string
		otherVersion   string
		otherFormat    Format
		expectError    bool
		errorSubstring string
	}{
		{
			name:         "same format successful comparison",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  PythonFormat,
			expectError:  false,
		},
		{
			name:         "same format successful comparison with pre-release",
			thisVersion:  "1.2.3a1",
			otherVersion: "1.2.3b2",
			otherFormat:  PythonFormat,
			expectError:  false,
		},
		{
			name:         "unknown format attempts upgrade - valid python format",
			thisVersion:  "1.2.3",
			otherVersion: "1.2.4",
			otherFormat:  UnknownFormat,
			expectError:  false,
		},
		{
			name:           "unknown format attempts upgrade - invalid python format",
			thisVersion:    "1.2.3",
			otherVersion:   "not/valid/python-format",
			otherFormat:    UnknownFormat,
			expectError:    true,
			errorSubstring: "invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, err := newPep440Version(test.thisVersion)
			require.NoError(t, err)

			otherVer := New(test.otherVersion, test.otherFormat)

			result, err := thisVer.Compare(otherVer)

			if test.expectError {
				require.Error(t, err)
				if test.errorSubstring != "" {
					assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
						"Expected error to contain '%s', got: %v", test.errorSubstring, err)
				}
			} else {
				assert.NoError(t, err)
				assert.Contains(t, []int{-1, 0, 1}, result, "Expected comparison result to be -1, 0, or 1")
			}
		})
	}
}

func TestPep440Version_Compare_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		setupFunc      func(testing.TB) (*Version, *Version)
		expectError    bool
		errorSubstring string
	}{
		{
			name: "nil version object",
			setupFunc: func(t testing.TB) (*Version, *Version) {
				thisVer := New("1.2.3", PythonFormat)
				return thisVer, nil
			},
			expectError:    true,
			errorSubstring: "no version provided for comparison",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			thisVer, otherVer := test.setupFunc(t)

			_, err := thisVer.Compare(otherVer)

			require.Error(t, err)
			if test.errorSubstring != "" {
				assert.True(t, strings.Contains(err.Error(), test.errorSubstring),
					"Expected error to contain '%s', got: %v", test.errorSubstring, err)
			}
		})
	}
}
