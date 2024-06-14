package search

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db"
	grypeDB "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var _ grypeDB.VulnerabilityStoreReader = (*mockVulnStore)(nil)

type mockVulnStore struct {
	data map[string]map[string][]grypeDB.Vulnerability
}

func (pr *mockVulnStore) GetVulnerability(namespace, id string) ([]grypeDB.Vulnerability, error) {
	//TODO implement me
	panic("implement me")
}

func newMockStore() *mockVulnStore {
	pr := mockVulnStore{
		data: make(map[string]map[string][]grypeDB.Vulnerability),
	}
	pr.stub()
	return &pr
}

func (pr *mockVulnStore) stub() {
	pr.data["nvd:cpe"] = map[string][]grypeDB.Vulnerability{
		"activerecord": {
			{
				PackageName:       "activerecord",
				VersionConstraint: "< 3.7.6",
				VersionFormat:     version.SemanticFormat.String(),
				ID:                "CVE-2017-fake-1",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*",
				},
				Namespace: "nvd:cpe",
			},
			{
				PackageName:       "activerecord",
				VersionConstraint: "< 3.7.4",
				VersionFormat:     version.SemanticFormat.String(),
				ID:                "CVE-2017-fake-2",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*",
				},
				Namespace: "nvd:cpe",
			},
			{
				PackageName:       "activerecord",
				VersionConstraint: "= 4.0.1",
				VersionFormat:     version.GemFormat.String(),
				ID:                "CVE-2017-fake-3",
				CPEs: []string{
					"cpe:2.3:*:activerecord:activerecord:4.0.1:*:*:*:*:*:*:*",
				},
				Namespace: "nvd:cpe",
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
				Namespace: "nvd:cpe",
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
				Namespace: "nvd:cpe",
			},
		},
		"funfun": {
			{
				PackageName:       "funfun",
				VersionConstraint: "= 5.2.1",
				VersionFormat:     version.UnknownFormat.String(),
				ID:                "CVE-2017-fake-6",
				CPEs: []string{
					"cpe:2.3:*:funfun:funfun:5.2.1:*:*:*:*:python:*:*",
					"cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*",
				},
				Namespace: "nvd:cpe",
			},
		},
		"sw": {
			{
				PackageName:       "sw",
				VersionConstraint: "< 1.0",
				VersionFormat:     version.UnknownFormat.String(),
				ID:                "CVE-2017-fake-7",
				CPEs: []string{
					"cpe:2.3:*:sw:sw:*:*:*:*:*:puppet:*:*",
				},
				Namespace: "nvd:cpe",
			},
		},
		"handlebars": {
			{
				PackageName:       "handlebars",
				VersionConstraint: "< 4.7.7",
				VersionFormat:     version.UnknownFormat.String(),
				ID:                "CVE-2021-23369",
				CPEs: []string{
					"cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:node.js:*:*",
				},
				Namespace: "nvd:cpe",
			},
		},
	}
}

func (pr *mockVulnStore) SearchForVulnerabilities(namespace, pkg string) ([]grypeDB.Vulnerability, error) {
	return pr.data[namespace][pkg], nil
}

func (pr *mockVulnStore) GetAllVulnerabilities() (*[]grypeDB.Vulnerability, error) {
	return nil, nil
}

func (pr *mockVulnStore) GetVulnerabilityNamespaces() ([]string, error) {
	keys := make([]string, 0, len(pr.data))
	for k := range pr.data {
		keys = append(keys, k)
	}

	return keys, nil
}

func TestFindMatchesByPackageCPE(t *testing.T) {
	matcher := match.RubyGemMatcher
	tests := []struct {
		name     string
		p        pkg.Package
		expected []match.Match
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "match from range",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:ra:*:ruby:*:*", ""),
					cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*", ""),
				},
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.5:rando1:*:ra:*:ruby:*:*", ""),
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*", ""),
						},
						Name:     "activerecord",
						Version:  "3.7.5",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								Namespace: "nvd:cpe",
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*"},
								Package: CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.5",
								},
							},
							Found: CPEResult{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
								VersionConstraint: "< 3.7.6 (semver)",
								VulnerabilityID:   "CVE-2017-fake-1",
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
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*", ""),
					cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*", ""),
				},
				Name:     "activerecord",
				Version:  "3.7.3",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-1",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*", ""),
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*", ""),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs: []string{
									"cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*",
								},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.3",
								},
							},
							Found: CPEResult{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*"},
								VersionConstraint: "< 3.7.6 (semver)",
								VulnerabilityID:   "CVE-2017-fake-1",
							},
							Matcher: matcher,
						},
					},
				},
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-2",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*", ""),
							cpe.Must("cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*", ""),
						},
						Name:     "activerecord",
						Version:  "3.7.3",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.3",
								},
							},
							Found: CPEResult{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*"},
								VersionConstraint: "< 3.7.4 (semver)",
								VulnerabilityID:   "CVE-2017-fake-2",
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
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*", ""),
				},
				Name:     "activerecord",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-3",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*", ""),
						},
						Name:     "activerecord",
						Version:  "4.0.1",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "activerecord",
									Version: "4.0.1",
								},
							},
							Found: CPEResult{
								CPEs:              []string{"cpe:2.3:*:activerecord:activerecord:4.0.1:*:*:*:*:*:*:*"},
								VersionConstraint: "= 4.0.1 (semver)",
								VulnerabilityID:   "CVE-2017-fake-3",
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
				ID:       pkg.ID(uuid.NewString()),
				Name:     "couldntgetthisrightcouldyou",
				Version:  "4.0.1",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:no_match:no_match:0.9.9:*:*:*:*:*:*:*", cpe.GeneratedSource),
				},
			},
			expected: []match.Match{},
		},
		{
			name: "fuzzy version match",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*", ""),
				},
				Name:    "awesome",
				Version: "98SE1",
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-4",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*", ""),
						},
						Name:    "awesome",
						Version: "98SE1",
					},

					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "awesome",
									Version: "98SE1",
								},
							},
							Found: CPEResult{
								CPEs:              []string{"cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*"},
								VersionConstraint: "< 98SP3 (unknown)",
								VulnerabilityID:   "CVE-2017-fake-4",
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
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*", ""),
				},
				Name:     "multiple",
				Version:  "1.0",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-5",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*", ""),
						},
						Name:     "multiple",
						Version:  "1.0",
						Language: syftPkg.Ruby,
						Type:     syftPkg.GemPkg,
					},

					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "multiple",
									Version: "1.0",
								},
							},
							Found: CPEResult{
								CPEs: []string{
									"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
									"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
								},
								VersionConstraint: "< 4.0 (unknown)",
								VulnerabilityID:   "CVE-2017-fake-5",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "filtered out match due to target_sw mismatch",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "funfun",
				Version:  "5.2.1",
				Language: syftPkg.Rust,
				Type:     syftPkg.RustPkg,
			},
			expected: []match.Match{},
		},
		{
			name: "target_sw mismatch with unsupported target_sw",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:sw:sw:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "sw",
				Version:  "0.1",
				Language: syftPkg.Erlang,
				Type:     syftPkg.HexPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-7",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:sw:sw:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "sw",
						Version:  "0.1",
						Language: syftPkg.Erlang,
						Type:     syftPkg.HexPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:sw:sw:*:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "sw",
									Version: "0.1",
								},
							},
							Found: CPEResult{
								CPEs: []string{
									"cpe:2.3:*:sw:sw:*:*:*:*:*:puppet:*:*",
								},
								VersionConstraint: "< 1.0 (unknown)",
								VulnerabilityID:   "CVE-2017-fake-7",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "match included even though multiple cpes are mismatch",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:rust:*:*", ""),
					cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:rails:*:*", ""),
					cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:ruby:*:*", ""),
					cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*", ""),
				},
				Name:     "funfun",
				Version:  "5.2.1",
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2017-fake-6",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:rust:*:*", ""),
							cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:rails:*:*", ""),
							cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:ruby:*:*", ""),
							cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*", ""),
						},
						Name:     "funfun",
						Version:  "5.2.1",
						Language: syftPkg.Python,
						Type:     syftPkg.PythonPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "funfun",
									Version: "5.2.1",
								},
							},
							Found: CPEResult{
								CPEs: []string{
									"cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*",
									"cpe:2.3:*:funfun:funfun:5.2.1:*:*:*:*:python:*:*",
								},
								VersionConstraint: "= 5.2.1 (unknown)",
								VulnerabilityID:   "CVE-2017-fake-6",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "Ensure target_sw mismatch does not apply to java packages",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "handlebars",
				Version:  "0.1",
				Language: syftPkg.Java,
				Type:     syftPkg.JavaPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2021-23369",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "handlebars",
						Version:  "0.1",
						Language: syftPkg.Java,
						Type:     syftPkg.JavaPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: CPEResult{
								CPEs: []string{
									"cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:node.js:*:*",
								},
								VersionConstraint: "< 4.7.7 (unknown)",
								VulnerabilityID:   "CVE-2021-23369",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "Ensure target_sw mismatch does not apply to java jenkins plugins packages",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "handlebars",
				Version:  "0.1",
				Language: syftPkg.Java,
				Type:     syftPkg.JenkinsPluginPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						ID: "CVE-2021-23369",
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "handlebars",
						Version:  "0.1",
						Language: syftPkg.Java,
						Type:     syftPkg.JenkinsPluginPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: CPEResult{
								CPEs: []string{
									"cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:node.js:*:*",
								},
								VersionConstraint: "< 4.7.7 (unknown)",
								VulnerabilityID:   "CVE-2021-23369",
							},
							Matcher: matcher,
						},
					},
				},
			},
		},
		{
			name: "package without CPEs returns error",
			p: pkg.Package{
				Name: "some-package",
			},
			expected: nil,
			wantErr: func(t require.TestingT, err error, i ...interface{}) {
				if !errors.Is(err, ErrEmptyCPEMatch) {
					t.Errorf("expected %v but got %v", ErrEmptyCPEMatch, err)
					t.FailNow()
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, err := db.NewVulnerabilityProvider(newMockStore())
			require.NoError(t, err)
			actual, err := ByPackageCPE(p, nil, test.p, matcher)
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			test.wantErr(t, err)
			assertMatchesUsingIDsForVulnerabilities(t, test.expected, actual)
			for idx, e := range test.expected {
				if d := cmp.Diff(e.Details, actual[idx].Details); d != "" {
					t.Errorf("unexpected match details (-want +got):\n%s", d)
				}
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
			vulnerabilityCPEs := make([]cpe.CPE, len(test.vulnerabilityCPEs))
			for idx, c := range test.vulnerabilityCPEs {
				vulnerabilityCPEs[idx] = cpe.Must(c, "")
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
				actualStrs[idx] = a.Attributes.BindToFmtString()
			}

			assert.ElementsMatch(t, test.expected, actualStrs)
		})
	}
}

func TestAddMatchDetails(t *testing.T) {
	tests := []struct {
		name     string
		existing []match.Detail
		new      match.Detail
		expected []match.Detail
	}{
		{
			name: "append new entry -- found not equal",
			existing: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"totally-different-match",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"totally-different-search",
						},
					},
					Found: CPEResult{
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
			existing: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: CPEParameters{
					Namespace: "totally-different",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: CPEParameters{
						Namespace: "totally-different",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
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
			existing: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
							"totally-different-search",
						},
					},
					Found: CPEResult{
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
			existing: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: "something else!",
				Found: CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
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
			existing: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: "something-else!",
			},
			expected: []match.Detail{
				{
					SearchedBy: CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: CPEResult{
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
		current  CPEResult
		other    CPEResult
		expected bool
	}{
		{
			name: "different version constraint",
			current: CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: CPEResult{
				VersionConstraint: "different-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			expected: false,
		},
		{
			name: "different number of CPEs",
			current: CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: CPEResult{
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
			current: CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"b-cpe",
				},
			},
			expected: false,
		},
		{
			name: "matches",
			current: CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: CPEResult{
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
