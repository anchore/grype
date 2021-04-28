package common

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func must(c syftPkg.CPE, e error) syftPkg.CPE {
	if e != nil {
		panic(e)
	}
	return c
}

type mockCPEProvider struct {
	data map[string]map[string][]*vulnerability.Vulnerability
}

func newMockProviderByCPE() *mockCPEProvider {
	pr := mockCPEProvider{
		data: make(map[string]map[string][]*vulnerability.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockCPEProvider) stub() {
	pr.data["nvd"] = map[string][]*vulnerability.Vulnerability{
		"activerecord": {
			{
				Constraint: version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
				ID:         "CVE-2017-fake-1",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*")),
				},
				Namespace: "nvd",
			},
			{
				Constraint: version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
				ID:         "CVE-2017-fake-2",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*")),
				},
				Namespace: "nvd",
			},
			{
				Constraint: version.MustGetConstraint("= 4.0.1", version.SemanticFormat),
				ID:         "CVE-2017-fake-3",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
				Namespace: "nvd",
			},
			{
				Constraint: version.MustGetConstraint("= 4.0.1", version.SemanticFormat),
				ID:         "CVE-2017-fake-3",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
				Namespace: "nvd",
			},
		},
		"awesome": {
			{
				Constraint: version.MustGetConstraint("< 98SP3", version.UnknownFormat),
				ID:         "CVE-2017-fake-4",
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*")),
				},
				Namespace: "nvd",
			},
		},
	}
}

func (pr *mockCPEProvider) GetByCPE(c syftPkg.CPE) ([]*vulnerability.Vulnerability, error) {
	return pr.data["nvd"][c.Product], nil
}

func TestFindMatchesByPackageCPE(t *testing.T) {
	matcher := match.RubyGemMatcher
	tests := []struct {
		name     string
		p        pkg.Package
		expected []match.Match
	}{
		{
			name: "match from range",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type:       match.FuzzyMatch,
					Confidence: 0.9,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:rando2:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:rando3:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.5",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					SearchKey: map[string]interface{}{
						"cpe": "cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:rando2:*:ruby:*:*",
					},
					SearchMatches: map[string]interface{}{
						"namespace":         "nvd",
						"cpes":              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
						"versionConstraint": "< 3.7.6 (semver)",
					},
					Matcher: matcher,
				},
			},
		},
		{
			name: "multiple matches",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.3",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type:       match.FuzzyMatch,
					Confidence: 0.9,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:rando3:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					SearchKey: map[string]interface{}{
						"cpe": "cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*",
					},
					SearchMatches: map[string]interface{}{
						"namespace":         "nvd",
						"cpes":              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
						"versionConstraint": "< 3.7.6 (semver)",
					},
					Matcher: matcher,
				},
				{
					Type:       match.FuzzyMatch,
					Confidence: 0.9,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-2",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:rando3:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					SearchKey: map[string]interface{}{
						"cpe": "cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:rando2:*:ruby:*:*",
					},
					SearchMatches: map[string]interface{}{
						"namespace":         "nvd",
						"cpes":              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*"},
						"versionConstraint": "< 3.7.4 (semver)",
					},
					Matcher: matcher,
				},
			},
		},
		{
			name: "exact match",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando1:*:rando2:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando4:*:rando3:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type:       match.FuzzyMatch,
					Confidence: 0.9,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-3",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando1:*:rando2:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:4.0.1:rando4:*:rando3:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "4.0.1",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					SearchKey: map[string]interface{}{
						"cpe": "cpe:2.3:*:activerecord:activerecord:4.0.1:rando1:*:rando2:*:ruby:*:*",
					},
					SearchMatches: map[string]interface{}{
						"namespace":         "nvd",
						"cpes":              []string{"cpe:2.3:*:couldntgetthisrightcouldyou:activerecord:4.0.1:*:*:*:*:*:*:*"},
						"versionConstraint": "= 4.0.1 (semver)",
					},
					Matcher: matcher,
				},
			},
		},
		{
			name: "no match",
			p: pkg.Package{
				Name:     "couldntgetthisrightcouldyou",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{},
		},
		{
			name: "fuzzy version match",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:rando2:*:dunno:*:*")),
				},
				Name:    "awesome",
				Version: "98SE1",
			},
			expected: []match.Match{
				{
					Type:       match.FuzzyMatch,
					Confidence: 0.9,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-4",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:rando2:*:dunno:*:*")),
						},
						Name:    "awesome",
						Version: "98SE1",
					},
					SearchKey: map[string]interface{}{
						"cpe": "cpe:2.3:*:awesome:awesome:98SE1:rando1:*:rando2:*:dunno:*:*",
					},
					SearchMatches: map[string]interface{}{
						"namespace":         "nvd",
						"cpes":              []string{"cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*"},
						"versionConstraint": "< 98SP3 (unknown)",
					},
					Matcher: matcher,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newMockProviderByCPE()
			actual, err := FindMatchesByPackageCPE(store, test.p, matcher)
			assert.NoError(t, err)
			assertMatchesUsingIDsForVulnerabilities(t, test.expected, actual)
		})
	}
}
