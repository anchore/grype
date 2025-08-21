package internal

import (
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

func newMockProviderByLanguage() vulnerability.Provider {
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

func expectedMatch(p pkg.Package, constraint string) []match.Match {
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

func expectedIgnored(pkgName string, fix string) []match.IgnoreRule {
	if fix == "" {
		return nil
	}
	return []match.IgnoreRule{
		{
			Vulnerability: "CVE-2017-fake-1",
			Reason:        "Fix",
			Namespace:     "github:language:ruby",
			FixState:      vulnerability.FixStateFixed.String(),
			Package: match.IgnoreRulePackage{
				Name:    pkgName,
				Version: fix,
			},
			MatchType: match.ExactDirectMatch,
		},
	}
}

func TestFindMatchesByPackageLanguage(t *testing.T) {
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
		// {
		// 	constraint: "< 1.7.6 (gem)",
		// 	expIgnores: expectedIgnored("nokogiri", "1.7.4+foo.1"),
		// 	p: pkg.Package{
		// 		ID:       pkg.ID(uuid.NewString()),
		// 		Name:     "nokogiri",
		// 		Version:  "1.7.5+foo.1",
		// 		Language: syftPkg.Ruby,
		// 		Type:     syftPkg.GemPkg,
		// 	},
		// },
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

	store := newMockProviderByLanguage()
	for _, c := range cases {
		t.Run(c.p.Name, func(t *testing.T) {
			actual, ignored, err := MatchPackageByLanguage(store, c.p, match.RubyGemMatcher)
			require.NoError(t, err)
			assert.ElementsMatch(t, ignored, c.expIgnores)
			if c.assertEmpty {
				assert.Empty(t, actual)
				return
			}
			assertMatchesUsingIDsForVulnerabilities(t, expectedMatch(c.p, c.constraint), actual)
		})
	}
}
