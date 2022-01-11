package common

import (
	"testing"

	grypeDB "github.com/anchore/grype/grype/db/v3"
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

var _ grypeDB.VulnerabilityStoreReader = (*mockVulnStore)(nil)

type mockVulnStore struct {
	data map[string]map[string][]grypeDB.Vulnerability
}

func newMockStore() *mockVulnStore {
	pr := mockVulnStore{
		data: make(map[string]map[string][]grypeDB.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockVulnStore) stub() {
	pr.data["nvd"] = map[string][]grypeDB.Vulnerability{
		"activerecord": {
			{
				PackageName:       "activerecord",
				VersionConstraint: "< 3.7.6",
				VersionFormat:     version.SemanticFormat.String(),
				ID:                "CVE-2017-fake-1",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*",
				},
				Namespace: "nvd",
			},
			{
				PackageName:       "activerecord",
				VersionConstraint: "< 3.7.4",
				VersionFormat:     version.SemanticFormat.String(),
				ID:                "CVE-2017-fake-2",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*",
				},
				Namespace: "nvd",
			},
			{
				PackageName:       "activerecord",
				VersionConstraint: "= 4.0.1",
				VersionFormat:     version.SemanticFormat.String(),
				ID:                "CVE-2017-fake-3",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:4.0.1:*:*:*:*:*:*:*",
				},
				Namespace: "nvd",
			},
		},
		"awesome": {
			{
				PackageName:       "awesome",
				VersionConstraint: "< 98SP3",
				VersionFormat:     version.UnknownFormat.String(),
				ID:                "CVE-2017-fake-4",
				CPEs: []string{
					"cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*",
				},
				Namespace: "nvd",
			},
		},
		"multiple": {
			{
				PackageName:       "multiple",
				VersionConstraint: "< 4.0",
				VersionFormat:     version.UnknownFormat.String(),
				ID:                "CVE-2017-fake-5",
				CPEs: []string{
					"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*",
					"cpe:2.3:*:multiple:multiple:3.0:*:*:*:*:*:*:*",
				},
				Namespace: "nvd",
			},
		},
	}
}

func (pr *mockVulnStore) GetVulnerability(namespace, pkg string) ([]grypeDB.Vulnerability, error) {
	return pr.data[namespace][pkg], nil
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
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:ra:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:ra:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.5",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								Namespace: "nvd",
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*"},
							},
							Found: FoundCPEs{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
								VersionConstraint: "< 3.7.6 (semver)",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "multiple matches",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*")),
					must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*")),
				},
				Name:     "activerecord",
				Version:  "3.7.3",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								CPEs: []string{
									"cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*",
								},
								Namespace: "nvd",
							},
							Found: FoundCPEs{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
								VersionConstraint: "< 3.7.6 (semver)",
							},
							Matcher: matcher,
						},
					},
				},
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-2",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*")),
							must(syftPkg.NewCPE("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*")),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*"},
								Namespace: "nvd",
							},
							Found: FoundCPEs{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*"},
								VersionConstraint: "< 3.7.4 (semver)",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "exact match",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*")),
				},
				Name:     "activerecord",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-3",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*")),
						},
						Name:     "activerecord",
						Version:  "4.0.1",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								CPEs:      []string{"cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd",
							},
							Found: FoundCPEs{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:4.0.1:*:*:*:*:*:*:*"},
								VersionConstraint: "= 4.0.1 (semver)",
							},
							Matcher: matcher,
						},
					},
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
					must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*")),
				},
				Name:    "awesome",
				Version: "98SE1",
			},
			expected: []match.Match{
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-4",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*")),
						},
						Name:    "awesome",
						Version: "98SE1",
					},

					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								CPEs:      []string{"cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*"},
								Namespace: "nvd",
							},
							Found: FoundCPEs{
								CPEs:              []string{"cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*"},
								VersionConstraint: "< 98SP3 (unknown)",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "multiple matched CPEs",
			p: pkg.Package{
				CPEs: []syftPkg.CPE{
					must(syftPkg.NewCPE("cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*")),
				},
				Name:     "multiple",
				Version:  "1.0",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{
					Type: match.FuzzyMatch,
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-5",
					},
					Package: pkg.Package{
						CPEs: []syftPkg.CPE{
							must(syftPkg.NewCPE("cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*")),
						},
						Name:     "multiple",
						Version:  "1.0",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					MatchDetails: []match.Details{
						{
							Confidence: 0.9,
							SearchedBy: SearchedByCPEs{
								CPEs:      []string{"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*"},
								Namespace: "nvd",
							},
							Found: FoundCPEs{
								CPEs: []string{
									"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
									"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
								},
								VersionConstraint: "< 4.0 (unknown)",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := FindMatchesByPackageCPE(vulnerability.NewProviderFromStore(newMockStore()), test.p, matcher)
			assert.NoError(t, err)
			assertMatchesUsingIDsForVulnerabilities(t, test.expected, actual)
			for idx, e := range test.expected {
				assert.Equal(t, e.MatchDetails, actual[idx].MatchDetails)
			}
		})
	}
}

func TestFilterCPEsByVersion(t *testing.T) {
	tests := []struct {
		name              string
		version           string
		vulnerabilityCPEs []string
		expected          []string
	}{
		{
			name:    "filter out by simple version",
			version: "1.0",
			vulnerabilityCPEs: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*",
			},
			expected: []string{
				"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
				"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// format strings to CPE objects...
			vulnerabilityCPEs := make([]syftPkg.CPE, len(test.vulnerabilityCPEs))
			for idx, c := range test.vulnerabilityCPEs {
				vulnerabilityCPEs[idx] = must(syftPkg.NewCPE(c))
			}

			versionObj, err := version.NewVersion(test.version, version.UnknownFormat)
			if err != nil {
				t.Fatalf("unable to get version: %+v", err)
			}

			// run the test subject...
			actual := filterCPEsByVersion(*versionObj, vulnerabilityCPEs)

			// format CPE objects to string...
			actualStrs := make([]string, len(actual))
			for idx, a := range actual {
				actualStrs[idx] = a.BindToFmtString()
			}

			assert.ElementsMatch(t, test.expected, actualStrs)
		})
	}
}

func TestAddMatchDetails(t *testing.T) {
	tests := []struct {
		name     string
		existing []match.Details
		new      match.Details
		expected []match.Details
	}{
		{
			name: "append new entry -- found not equal",
			existing: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Details{
				SearchedBy: SearchedByCPEs{
					Namespace: "nvd",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: FoundCPEs{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"totally-different-match",
					},
				},
			},
			expected: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"totally-different-search",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"totally-different-match",
						},
					},
				},
			},
		},
		{
			name: "append new entry -- searchedBy merge fails",
			existing: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Details{
				SearchedBy: SearchedByCPEs{
					Namespace: "totally-different",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: FoundCPEs{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "totally-different",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
		},
		{
			name: "merge with exiting entry",
			existing: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Details{
				SearchedBy: SearchedByCPEs{
					Namespace: "nvd",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: FoundCPEs{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
							"totally-different-search",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
		},
		{
			name: "no addition - bad new searchedBy type",
			existing: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Details{
				SearchedBy: "something else!",
				Found: FoundCPEs{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
		},
		{
			name: "no addition - bad new found type",
			existing: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Details{
				SearchedBy: SearchedByCPEs{
					Namespace: "nvd",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: "something-else!",
			},
			expected: []match.Details{
				{
					SearchedBy: SearchedByCPEs{
						Namespace: "nvd",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: FoundCPEs{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, addMatchDetails(test.existing, test.new))
		})
	}
}

func TestCPESearchHit_Equals(t *testing.T) {
	tests := []struct {
		name     string
		current  FoundCPEs
		other    FoundCPEs
		expected bool
	}{
		{
			name: "different version constraint",
			current: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: FoundCPEs{
				VersionConstraint: "different-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			expected: false,
		},
		{
			name: "different number of CPEs",
			current: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
					"b-cpe",
				},
			},
			expected: false,
		},
		{
			name: "different CPE value",
			current: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"b-cpe",
				},
			},
			expected: false,
		},
		{
			name: "matches",
			current: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: FoundCPEs{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, test.current.Equals(test.other))
		})
	}
}
