package internal

import (
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func newMockProviderRuby() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-1",
				Namespace: "github:language:ruby",
			},
			PackageName: "activerecord",
			// make sure we find it with semVer constraint
			Constraint: version.MustGetConstraint("< 3.7.6", version.GemFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-2",
				Namespace: "github:language:ruby",
			},
			PackageName: "activerecord",
			Constraint:  version.MustGetConstraint("< 3.7.4", version.GemFormat),
		},
		{
			// ignore filter entry
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-2",
				Namespace: "github:language:ruby",
			},
			PackageName: "activerecord",
			Constraint:  version.MustGetConstraint("< 3.7.4", version.GemFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-1",
				Namespace: "github:language:ruby",
			},
			PackageName: "nokogiri",
			// make sure we find it with gem version constraint
			Constraint: version.MustGetConstraint("< 1.7.6", version.GemFormat),
			// detail a fix by vendor "foo"
			Fix: vulnerability.Fix{
				Versions: []string{"1.7.4+foo.1"},
				State:    vulnerability.FixStateFixed,
			},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-2",
				Namespace: "github:language:ruby",
			},
			PackageName: "nokogiri",
			Constraint:  version.MustGetConstraint("< 1.7.4", version.GemFormat),
		},
	}...)
}

func expectedMatchRuby(p pkg.Package, constraint string) []match.Match {
	return []match.Match{
		{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2017-fake-1",
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: match.EcosystemParameters{
						Language:  "ruby",
						Namespace: "github:language:ruby",
						Package:   match.PackageParameter{Name: p.Name, Version: p.Version},
					},
					Found: match.EcosystemResult{
						VulnerabilityID:   "CVE-2017-fake-1",
						VersionConstraint: constraint,
					},
					Matcher: match.RubyGemMatcher,
				},
			},
		},
	}
}

func TestFindMatchesByPackageRuby(t *testing.T) {
	cases := []struct {
		p           pkg.Package
		constraint  string
		expIgnores  []match.IgnoreRule
		assertEmpty bool
	}{
		{
			constraint: "< 3.7.6 (gem)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "activerecord",
				Version:  "3.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
		},
		{
			constraint: "< 1.7.6 (gem)",
			// no ignores expected as version doesn't contain +foo
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "nokogiri",
				Version:  "1.7.5",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
		},
		{
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "nokogiri",
				Version:  "unknown",
				Language: syftPkg.Ruby,
				Type:     syftPkg.GemPkg,
			},
			assertEmpty: true,
		},
	}

	store := newMockProviderRuby()
	for _, c := range cases {
		t.Run(c.p.Name, func(t *testing.T) {
			actual, ignored, err := MatchPackageByLanguage(store, c.p, match.RubyGemMatcher)
			require.NoError(t, err)
			assert.ElementsMatch(t, ignored, c.expIgnores)
			if c.assertEmpty {
				assert.Empty(t, actual)
				return
			}
			assertMatchesUsingIDsForVulnerabilities(t, expectedMatchRuby(c.p, c.constraint), actual)
		})
	}
}

// Golang tests

func expectedMatchGolang(p pkg.Package, vulnConstraint map[string]string) []match.Match {
	matches := make([]match.Match, 0, len(vulnConstraint))
	// get sorted keys for consistent test results
	keys := make([]string, 0, len(vulnConstraint))
	for k := range vulnConstraint {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, vuln := range keys {
		constraint := vulnConstraint[vuln]
		matches = append(matches, match.Match{
			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: vuln,
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type: match.ExactDirectMatch,
					// Confidence zero since ecosystems get hardcoded confidence of zero
					Confidence: 1,
					SearchedBy: match.EcosystemParameters{
						Language:  "go",
						Namespace: "github:language:go",
						Package:   match.PackageParameter{Name: p.Name, Version: p.Version},
					},
					Found: match.EcosystemResult{
						VulnerabilityID:   vuln,
						VersionConstraint: constraint,
					},
					Matcher: match.GoModuleMatcher,
				},
			},
		})
	}
	return matches
}

func newMockProviderGolang() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-1",
				Namespace: "github:language:go",
			},
			PackageName: "package",
			Constraint:  version.MustGetConstraint("< 1.2.4", version.GolangFormat),
			Fix: vulnerability.Fix{
				Versions: []string{"1.2.4"},
				State:    vulnerability.FixStateFixed,
			},
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-2",
				Namespace: "github:language:go",
			},
			PackageName: "package",
			Constraint:  version.MustGetConstraint("< 1.3.1", version.GolangFormat),
			Fix: vulnerability.Fix{
				Versions: []string{"1.3.1"},
				State:    vulnerability.FixStateFixed,
			},
		},
		{
			// unaffected entry
			Reference: vulnerability.Reference{
				ID:        "CVE-2017-fake-1",
				Namespace: "github:language:go",
			},
			PackageName: "package",
			Constraint:  version.MustGetConstraint("= 1.2.1+foo.1", version.GolangFormat),
			Fix: vulnerability.Fix{
				Versions: []string{"1.2.1+foo.1"},
				State:    vulnerability.FixStateFixed,
			},
			Unaffected: true,
		},
	}...)
}

func TestFindMatchesByPackageGolang(t *testing.T) {
	cases := []struct {
		p          pkg.Package
		expMatches map[string]string
	}{
		{
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "package",
				Version:  "1.2.3",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			expMatches: map[string]string{"CVE-2017-fake-2": "< 1.3.1 (go)", "CVE-2017-fake-1": "< 1.2.4 (go)"},
		},
		{
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "package",
				Version:  "1.2.5",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			expMatches: map[string]string{"CVE-2017-fake-2": "< 1.3.1 (go)"},
		},
		{
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "package",
				Version:  "1.2.1+foo.1",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
			},
			expMatches: map[string]string{"CVE-2017-fake-2": "< 1.3.1 (go)"},
		},
	}

	store := newMockProviderGolang()
	for _, c := range cases {
		t.Run(c.p.Name, func(t *testing.T) {
			actual, ignored, err := MatchPackageByLanguage(store, c.p, match.GoModuleMatcher)
			// sort for consistency
			slices.SortFunc(actual, func(a, b match.Match) int {
				return strings.Compare(a.Vulnerability.ID, b.Vulnerability.ID)
			})
			require.NoError(t, err)
			assert.Empty(t, ignored)
			assertMatchesUsingIDsForVulnerabilities(t, expectedMatchGolang(c.p, c.expMatches), actual)
		})
	}
}
