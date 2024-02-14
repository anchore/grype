package match

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var (
	allMatches = []Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-123",
				Namespace: "debian-vulns",
				Fix: vulnerability.Fix{
					State: grypeDb.FixedState,
				},
			},
			Package: pkg.Package{
				ID:        pkg.ID(uuid.NewString()),
				Name:      "dive",
				Version:   "0.5.2",
				Type:      "deb",
				Locations: file.NewLocationSet(file.NewLocation("/path/that/has/dive")),
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-456",
				Namespace: "ruby-vulns",
				Fix: vulnerability.Fix{
					State: grypeDb.NotFixedState,
				},
			},
			Package: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "reach",
				Version:  "100.0.50",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
				Locations: file.NewLocationSet(file.NewVirtualLocation("/real/path/with/reach",
					"/virtual/path/that/has/reach")),
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-457",
				Namespace: "ruby-vulns",
				Fix: vulnerability.Fix{
					State: grypeDb.WontFixState,
				},
			},
			Package: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "beach",
				Version:  "100.0.51",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
				Locations: file.NewLocationSet(file.NewVirtualLocation("/real/path/with/beach",
					"/virtual/path/that/has/beach")),
			},
		},
		{
			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-458",
				Namespace: "ruby-vulns",
				Fix: vulnerability.Fix{
					State: grypeDb.UnknownFixState,
				},
			},
			Package: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "speach",
				Version:  "100.0.52",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
				Locations: file.NewLocationSet(file.NewVirtualLocation("/real/path/with/speach",
					"/virtual/path/that/has/speach")),
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
			expectedRemainingMatches: []Match{
				allMatches[2],
				allMatches[3],
			},
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
				allMatches[2],
				allMatches[3],
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
		{
			name:       "ignore matches without fix",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{FixState: string(grypeDb.NotFixedState)},
				{FixState: string(grypeDb.WontFixState)},
				{FixState: string(grypeDb.UnknownFixState)},
			},
			expectedRemainingMatches: []Match{
				allMatches[0],
			},
			expectedIgnoredMatches: []IgnoredMatch{
				{
					Match: allMatches[1],
					AppliedIgnoreRules: []IgnoreRule{
						{
							FixState: "not-fixed",
						},
					},
				},
				{
					Match: allMatches[2],
					AppliedIgnoreRules: []IgnoreRule{
						{
							FixState: "wont-fix",
						},
					},
				},
				{
					Match: allMatches[3],
					AppliedIgnoreRules: []IgnoreRule{
						{
							FixState: "unknown",
						},
					},
				},
			},
		},
		{
			name:       "ignore matches on namespace",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{Namespace: "ruby-vulns"},
			},
			expectedRemainingMatches: []Match{
				allMatches[0],
			},
			expectedIgnoredMatches: []IgnoredMatch{
				{
					Match: allMatches[1],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Namespace: "ruby-vulns",
						},
					},
				},
				{
					Match: allMatches[2],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Namespace: "ruby-vulns",
						},
					},
				},
				{
					Match: allMatches[3],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Namespace: "ruby-vulns",
						},
					},
				},
			},
		},
		{
			name:       "ignore matches on language",
			allMatches: allMatches,
			ignoreRules: []IgnoreRule{
				{
					Package: IgnoreRulePackage{
						Language: string(syftPkg.Ruby),
					},
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
							Package: IgnoreRulePackage{
								Language: string(syftPkg.Ruby),
							},
						},
					},
				},
				{
					Match: allMatches[2],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Package: IgnoreRulePackage{
								Language: string(syftPkg.Ruby),
							},
						},
					},
				},
				{
					Match: allMatches[3],
					AppliedIgnoreRules: []IgnoreRule{
						{
							Package: IgnoreRulePackage{
								Language: string(syftPkg.Ruby),
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			actualRemainingMatches, actualIgnoredMatches := ApplyIgnoreRules(sliceToMatches(testCase.allMatches), testCase.ignoreRules)

			assertMatchOrder(t, testCase.expectedRemainingMatches, actualRemainingMatches.Sorted())
			assertIgnoredMatchOrder(t, testCase.expectedIgnoredMatches, actualIgnoredMatches)

		})
	}
}

func sliceToMatches(s []Match) Matches {
	matches := NewMatches()
	matches.Add(s...)
	return matches
}

var (
	exampleMatch = Match{
		Vulnerability: vulnerability.Vulnerability{
			ID: "CVE-2000-1234",
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "a-pkg",
			Version: "1.0",
			Locations: file.NewLocationSet(
				file.NewLocation("/some/path"),
				file.NewVirtualLocation("/some/path", "/some/virtual/path"),
			),
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
					Location: exampleMatch.Package.Locations.ToSlice()[0].RealPath,
				},
			},
			expected: true,
		},
		{
			name:  "rule applies via package location virtual path",
			match: exampleMatch,
			rule: IgnoreRule{
				Package: IgnoreRulePackage{
					Location: exampleMatch.Package.Locations.ToSlice()[1].AccessPath,
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
