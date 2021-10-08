package match

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"

	"github.com/stretchr/testify/assert"
)

var (
	allMatches = []Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-123",
			},
			Package: pkg.Package{
				Name:    "dive",
				Version: "0.5.2",
				Type:    "deb",
				Locations: []source.Location{
					{
						RealPath: "/path/that/has/dive",
					},
				},
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID: "CVE-456",
			},
			Package: pkg.Package{
				Name:    "reach",
				Version: "100.0.50",
				Type:    "gem",
				Locations: []source.Location{
					{
						RealPath:    "/real/path/with/reach",
						VirtualPath: "/virtual/path/that/has/reach",
					},
				},
			},
		},
	}
)

func TestApplyIgnoreRules(t *testing.T) {
	cases := []struct {
		name                     string
		allMatches               []Match
		ignoreRules              []IgnoreRule
		expectedRemainingMatches []Match
		expectedIgnoredMatches   []IgnoredMatch
	}{
		{
			name:                     "no ignore rules",
			allMatches:               allMatches,
			ignoreRules:              nil,
			expectedRemainingMatches: allMatches,
			expectedIgnoredMatches:   nil,
		},
		{
			name:       "no applicable ignore rules",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{
					Vulnerability: "CVE-789",
				},
				{
					Package: IgnoreRulePackage{
						Name:    "bashful",
						Version: "5",
						Type:    "npm",
					},
				},
				{
					Package: IgnoreRulePackage{
						Name:    "reach",
						Version: "3000",
					},
				},
			},
			expectedRemainingMatches: allMatches,
			expectedIgnoredMatches:   nil,
		},
		{
			name:       "ignore all matches",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{
					Vulnerability: "CVE-123",
				},
				{
					Package: IgnoreRulePackage{
						Location: "/virtual/path/that/has/reach",
					},
				},
			},
			expectedRemainingMatches: nil,
			expectedIgnoredMatches: []IgnoredMatch{
				{
					Match: allMatches[0],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Vulnerability: "CVE-123",
						},
					},
				},
				{
					Match: allMatches[1],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Package: IgnoreRulePackage{
								Location: "/virtual/path/that/has/reach",
							},
						},
					},
				},
			},
		},
		{
			name:       "ignore subset of matches",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{
					Vulnerability: "CVE-456",
				},
			},
			expectedRemainingMatches: []Match{
				allMatches[0],
			},
			expectedIgnoredMatches: []IgnoredMatch{
				{
					Match: allMatches[1],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Vulnerability: "CVE-456",
						},
					},
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			failOnlyFixed := false
			locationComparerOption := cmp.Comparer(func(x, y source.Location) bool {
				return x.RealPath == y.RealPath && x.VirtualPath == y.VirtualPath
			})

			actualRemainingMatches, actualIgnoredMatches := ApplyIgnoreRules(sliceToMatches(testCase.allMatches), testCase.ignoreRules, failOnlyFixed)

			if diff := cmp.Diff(testCase.expectedRemainingMatches, matchesToSlice(actualRemainingMatches), locationComparerOption); diff != "" {
				t.Errorf("unexpected diff in remaining matches (-expected +actual):\n%s", diff)
			}

			if diff := cmp.Diff(testCase.expectedIgnoredMatches, actualIgnoredMatches, locationComparerOption); diff != "" {
				t.Errorf("unexpected diff in ignored matches (-expected +actual):\n%s", diff)
			}
		})
	}
}

func sliceToMatches(s []Match) Matches {
	matches := NewMatches()
	matches.add("123", s...)
	return matches
}

func matchesToSlice(m Matches) []Match {
	slice := m.Sorted()
	if len(slice) == 0 {
		return nil
	}

	return slice
}

var (
	exampleMatch = Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2000-1234",
		},
		Package: pkg.Package{
			Name:    "a-pkg",
			Version: "1.0",
			Locations: []source.Location{
				{
					RealPath: "/some/path",
				},
				{
					RealPath:    "/some/path",
					VirtualPath: "/some/virtual/path",
				},
			},
			Type: "rpm",
		},
	}
)

func TestShouldIgnore(t *testing.T) {
	cases := []struct {
		name     string
		match    Match
		rule     IgnoreRule
		expected bool
	}{
		{
			name:     "empty rule",
			match:    exampleMatch,
			rule:     IgnoreRule{},
			expected: false,
		},
		{
			name:  "rule applies via vulnerability ID",
			match: exampleMatch,
			rule: IgnoreRule{
				Vulnerability: exampleMatch.Vulnerability.ID,
			},
			expected: true,
		},
		{
			name:  "rule applies via package name",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Name: exampleMatch.Package.Name,
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package version",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Version: exampleMatch.Package.Version,
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package type",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Type: string(exampleMatch.Package.Type),
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package location real path",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Location: exampleMatch.Package.Locations[0].RealPath,
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package location virtual path",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Location: exampleMatch.Package.Locations[1].VirtualPath,
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package location glob",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Location: "/some/**",
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via multiple fields",
			match: exampleMatch,
			rule: IgnoreRule{
				Vulnerability: exampleMatch.Vulnerability.ID,
				Package: IgnoreRulePackage{
					Type: string(exampleMatch.Package.Type),
				},
			},
			expected: true,
		},
		{
			name:  "rule doesn't apply despite some fields matching",
			match: exampleMatch,
			rule: IgnoreRule{
				Vulnerability: exampleMatch.Vulnerability.ID,
				Package: IgnoreRulePackage{
					Name:    "not-the-right-package",
					Version: exampleMatch.Package.Version,
				},
			},
			expected: false,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actual := shouldIgnore(testCase.match, testCase.rule)
			assert.Equal(t, testCase.expected, actual)
		})
	}
}
