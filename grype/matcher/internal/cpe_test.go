package internal

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func newCPETestStore() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-1",
				Namespace: "nvd:cpe",
			},
			PackageName: "activerecord",
			Constraint:  version.MustGetConstraint("< 3.7.6", version.SemanticFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:rails:*:*", "")},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-2",
				Namespace: "nvd:cpe",
			},
			PackageName: "activerecord",
			Constraint:  version.MustGetConstraint("< 3.7.4", version.SemanticFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*", "")},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-3",
				Namespace: "nvd:cpe",
			},
			PackageName: "activerecord",
			Constraint:  version.MustGetConstraint("= 4.0.1", version.GemFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:*:activerecord:activerecord:4.0.1:*:*:*:*:*:*:*", "")},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-4",
				Namespace: "nvd:cpe",
			},
			PackageName: "awesome",
			Constraint:  version.MustGetConstraint("< 98SP3", version.UnknownFormat),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:awesome:awesome:*:*:*:*:*:*:*:*", ""),
			},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-5",
				Namespace: "nvd:cpe",
			},
			PackageName: "multiple",
			Constraint:  version.MustGetConstraint("< 4.0", version.UnknownFormat),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*", ""),
				cpe.Must("cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*", ""),
				cpe.Must("cpe:2.3:*:multiple:multiple:2.0:*:*:*:*:*:*:*", ""),
				cpe.Must("cpe:2.3:*:multiple:multiple:3.0:*:*:*:*:*:*:*", ""),
			},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-6",
				Namespace: "nvd:cpe",
			},
			PackageName: "funfun",
			Constraint:  version.MustGetConstraint("= 5.2.1", version.UnknownFormat),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:*:funfun:funfun:5.2.1:*:*:*:*:python:*:*", ""),
				cpe.Must("cpe:2.3:*:funfun:funfun:*:*:*:*:*:python:*:*", ""),
			},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-7",
				Namespace: "nvd:cpe",
			},
			PackageName: "sw",
			Constraint:  version.MustGetConstraint("< 1.0", version.UnknownFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:*:sw:sw:*:*:*:*:*:puppet:*:*", "")},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2021-23369",
				Namespace: "nvd:cpe",
			},
			PackageName: "handlebars",
			Constraint:  version.MustGetConstraint("< 4.7.7", version.UnknownFormat),
			CPEs:        []cpe.CPE{cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:node.js:*:*", "")},
		},
	}...)
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-1"},
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
							SearchedBy: match.CPEParameters{
								Namespace: "nvd:cpe",
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*"},
								Package: match.CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.5",
								},
							},
							Found: match.CPEResult{
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
			name: "fallback to package version",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando1:*:ra:*:ruby:*:*", ""),
					cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando4:*:re:*:rails:*:*", ""),
				},
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{
				{

					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-1"},
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando1:*:ra:*:ruby:*:*", ""),
							cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando4:*:re:*:rails:*:*", ""),
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
							SearchedBy: match.CPEParameters{
								Namespace: "nvd:cpe",
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.5:rando4:*:re:*:rails:*:*"},
								Package: match.CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.5",
								},
							},
							Found: match.CPEResult{
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
			name: "suppress matching when missing version",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando1:*:ra:*:ruby:*:*", ""),
					cpe.Must("cpe:2.3:*:activerecord:activerecord:unknown:rando4:*:re:*:rails:*:*", ""),
				},
				Name:     "activerecord",
				Version:  "",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			expected: []match.Match{},
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-1"},
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
							SearchedBy: match.CPEParameters{
								CPEs: []string{
									"cpe:2.3:*:activerecord:activerecord:3.7.3:rando4:*:re:*:rails:*:*",
								},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.3",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-2"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:activerecord:activerecord:3.7.3:rando1:*:ra:*:ruby:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "activerecord",
									Version: "3.7.3",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-3"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:*:activerecord:4.0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "activerecord",
									Version: "4.0.1",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-4"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:awesome:awesome:98SE1:rando1:*:ra:*:dunno:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "awesome",
									Version: "98SE1",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-5"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "multiple",
									Version: "1.0",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-7"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:sw:sw:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "sw",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2017-fake-6"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:*:funfun:funfun:5.2.1:*:*:*:*:python:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "funfun",
									Version: "5.2.1",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2021-23369"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
						Reference: vulnerability.Reference{ID: "CVE-2021-23369"},
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
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
			name: "Ensure target_sw mismatch does not apply to binary packages",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "handlebars",
				Version:  "0.1",
				Language: syftPkg.UnknownLanguage,
				Type:     syftPkg.BinaryPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-23369"},
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "handlebars",
						Version:  "0.1",
						Language: syftPkg.UnknownLanguage,
						Type:     syftPkg.BinaryPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
			name: "Ensure target_sw mismatch does not apply to unknown packages",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "handlebars",
				Version:  "0.1",
				Language: syftPkg.UnknownLanguage,
				Type:     syftPkg.UnknownPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-23369"},
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "handlebars",
						Version:  "0.1",
						Language: syftPkg.UnknownLanguage,
						Type:     syftPkg.UnknownPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
		{
			name: "Ensure match is kept for target software that matches the syft package language type",
			p: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
				},
				Name:     "handlebars",
				Version:  "0.1",
				Language: syftPkg.JavaScript,
				Type:     syftPkg.NpmPkg,
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2021-23369"},
					},
					Package: pkg.Package{
						CPEs: []cpe.CPE{
							cpe.Must("cpe:2.3:a:handlebarsjs:handlebars:*:*:*:*:*:*:*:*", ""),
						},
						Name:     "handlebars",
						Version:  "0.1",
						Language: syftPkg.JavaScript,
						Type:     syftPkg.NpmPkg,
					},
					Details: []match.Detail{
						{
							Type:       match.CPEMatch,
							Confidence: 0.9,
							SearchedBy: match.CPEParameters{
								CPEs:      []string{"cpe:2.3:a:handlebarsjs:handlebars:0.1:*:*:*:*:*:*:*"},
								Namespace: "nvd:cpe",
								Package: match.CPEPackageParameter{
									Name:    "handlebars",
									Version: "0.1",
								},
							},
							Found: match.CPEResult{
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
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := MatchPackageByCPEs(newCPETestStore(), test.p, matcher)
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			test.wantErr(t, err)
			assertMatchesUsingIDsForVulnerabilities(t, test.expected, actual)
			for idx, e := range test.expected {
				if idx < len(actual) {
					if d := cmp.Diff(e.Details, actual[idx].Details); d != "" {
						t.Errorf("unexpected match details (-want +got):\n%s", d)
					}
				} else {
					t.Errorf("expected match details (-want +got)\n%+v:\n", e.Details)
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
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: match.CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: match.CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"totally-different-match",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"totally-different-search",
						},
					},
					Found: match.CPEResult{
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
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: match.CPEParameters{
					Namespace: "totally-different",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: match.CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
				{
					SearchedBy: match.CPEParameters{
						Namespace: "totally-different",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
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
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: match.CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"totally-different-search",
					},
				},
				Found: match.CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
							"totally-different-search",
						},
					},
					Found: match.CPEResult{
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
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: "something else!",
				Found: match.CPEResult{
					VersionConstraint: "< 2.0 (unknown)",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
					},
				},
			},
			expected: []match.Detail{
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
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
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
						VersionConstraint: "< 2.0 (unknown)",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:*:*:*:*:*:*:*:*",
						},
					},
				},
			},
			new: match.Detail{
				SearchedBy: match.CPEParameters{
					Namespace: "nvd:cpe",
					CPEs: []string{
						"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
					},
				},
				Found: "something-else!",
			},
			expected: []match.Detail{
				{
					SearchedBy: match.CPEParameters{
						Namespace: "nvd:cpe",
						CPEs: []string{
							"cpe:2.3:*:multiple:multiple:1.0:*:*:*:*:*:*:*",
						},
					},
					Found: match.CPEResult{
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
		current  match.CPEResult
		other    match.CPEResult
		expected bool
	}{
		{
			name: "different version constraint",
			current: match.CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: match.CPEResult{
				VersionConstraint: "different-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			expected: false,
		},
		{
			name: "different number of CPEs",
			current: match.CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: match.CPEResult{
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
			current: match.CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: match.CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"b-cpe",
				},
			},
			expected: false,
		},
		{
			name: "matches",
			current: match.CPEResult{
				VersionConstraint: "current-constraint",
				CPEs: []string{
					"a-cpe",
				},
			},
			other: match.CPEResult{
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
