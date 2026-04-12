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
	"github.com/anchore/syft/syft/cpe"
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
		unaffected bool
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
			unaffected: true, // this vuln matches an unaffected entry
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
			if c.unaffected {
				assert.NotEmpty(t, ignored)
			} else {
				assert.Empty(t, ignored)
			}
			assertMatchesUsingIDsForVulnerabilities(t, expectedMatchGolang(c.p, c.expMatches), actual)
		})
	}
}

func Test_unaffectedPackageIgnoreRules(t *testing.T) {
	someProjectCPE := cpe.Must(`cpe:2.3:a:some_vendor:some_project:*:*:*:*:*:*:*:*`, cpe.DeclaredSource)
	provider := mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference:   vulnerability.Reference{ID: "vuln1", Namespace: "github:language:python"},
			Constraint:  version.MustGetConstraint("< 1.2.3", version.PythonFormat),
			PackageName: "some_project",
			Unaffected:  false,
		},
		{
			Reference:   vulnerability.Reference{ID: "vuln2", Namespace: "github:language:python"},
			Constraint:  version.MustGetConstraint("< 1.2.3", version.PythonFormat),
			PackageName: "some_project",
			Unaffected:  true,
		},
		{
			Reference:   vulnerability.Reference{ID: "vuln2", Namespace: "nvd:cpe"},
			Constraint:  version.MustGetConstraint("< 1.2.3", version.PythonFormat),
			PackageName: "some_project",
			CPEs:        []cpe.CPE{someProjectCPE},
			Unaffected:  false,
		},
	}...)

	tests := []struct {
		name     string
		pkg      pkg.Package
		expected []match.IgnoreFilter
	}{
		{
			name: "matching unaffected",
			pkg: pkg.Package{
				Name:     "some_project",
				Version:  "1.2.2",
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
				CPEs:     []cpe.CPE{someProjectCPE},
			},
			expected: []match.IgnoreFilter{
				match.IgnoreRule{
					Vulnerability:  "vuln2",
					IncludeAliases: true,
					Reason:         "UnaffectedPackageEntry",
					Package: match.IgnoreRulePackage{
						Name:    "some_project",
						Version: "1.2.2",
						Type:    string(syftPkg.PythonPkg),
					},
				},
			},
		},
		{
			name: "not unaffected by version",
			pkg: pkg.Package{
				Name:     "some_project",
				Version:  "1.2.4",
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
				CPEs:     []cpe.CPE{someProjectCPE},
			},
			expected: nil,
		},
		{
			name: "not unaffected by name",
			pkg: pkg.Package{
				Name:     "some_other_project",
				Version:  "1.2.2",
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
				CPEs:     []cpe.CPE{someProjectCPE},
			},
			expected: nil,
		},
		{
			name: "not unaffected by type",
			pkg: pkg.Package{
				Name:     "some_project",
				Version:  "1.2.2",
				Language: syftPkg.Go,
				Type:     syftPkg.GoModulePkg,
				CPEs:     []cpe.CPE{someProjectCPE},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ignoreRules, err := MatchPackageByEcosystemPackageName(provider, tt.pkg, tt.pkg.Name, "")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, ignoreRules)
		})
	}
}

// TestMatchPackageByLanguage_RootIONPM verifies that a rootio npm package:
// - finds upstream CVEs via the stripped package name
// - has matches suppressed when a rootio NAK record covers the installed version
func TestMatchPackageByLanguage_RootIONPM(t *testing.T) {
	// upstream disclosure: CVE affects plain semver
	disclosure := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2022-25883",
			Namespace: "github:language:javascript",
		},
		PackageName: "semver",
		Constraint:  version.MustGetConstraint("< 7.5.2", version.SemanticFormat),
	}

	// rootio NAK: @rootio/semver at or above rootio fix is unaffected.
	// RelatedVulnerabilities bridges ROOT-APP-NPM-... to CVE-2022-25883 so
	// disclosures.Remove(naks) can match by identity.
	nak := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "ROOT-APP-NPM-CVE-2022-25883",
			Namespace: "github:language:javascript",
		},
		PackageName: "@rootio/semver",
		Constraint:  version.MustGetConstraint(">= 7.5.2-root.io.1", version.SemanticFormat),
		Unaffected:  true,
		RelatedVulnerabilities: []vulnerability.Reference{
			{ID: "CVE-2022-25883"},
		},
	}

	tests := []struct {
		name          string
		pkgVersion    string
		vulns         []vulnerability.Vulnerability
		expectMatches int
		expectIgnores int
	}{
		{
			// Below the rootio fix: disclosure is found via stripped name "semver".
			// No NAK applies, so no ignore filters.
			name:          "rootio npm package below fix — disclosure found via stripped name",
			pkgVersion:    "7.5.1",
			vulns:         []vulnerability.Vulnerability{disclosure},
			expectMatches: 1,
			expectIgnores: 0,
		},
		{
			// At the rootio fix: 7.5.2-root.io.1 is a semver pre-release, so it is
			// still < 7.5.2 and the disclosure matches. The NAK produces an ignore
			// filter (containing CVE-2022-25883) that the caller applies to suppress
			// the match. This function returns the match + the ignore filter.
			name:          "rootio npm package at rootio fix — disclosure matched but NAK ignore filter returned",
			pkgVersion:    "7.5.2-root.io.1",
			vulns:         []vulnerability.Vulnerability{disclosure, nak},
			expectMatches: 1,
			// ConstructIgnoreFilters produces one rule per ID:
			// ROOT-APP-NPM-CVE-2022-25883 and CVE-2022-25883 (from RelatedVulnerabilities)
			expectIgnores: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "@rootio/semver",
				Version:  tt.pkgVersion,
				Language: syftPkg.JavaScript,
				Type:     syftPkg.NpmPkg,
			}

			vp := mock.VulnerabilityProvider(tt.vulns...)
			matches, ignores, err := MatchPackageByLanguage(vp, p, match.JavascriptMatcher)
			require.NoError(t, err)
			assert.Len(t, matches, tt.expectMatches, "unexpected match count for %q", tt.name)
			assert.Len(t, ignores, tt.expectIgnores, "unexpected ignore count for %q", tt.name)

			// For the patched case, verify the ignore filter covers the upstream CVE
			if tt.expectIgnores > 0 {
				var ignoredIDs []string
				for _, ig := range ignores {
					if rule, ok := ig.(match.IgnoreRule); ok {
						ignoredIDs = append(ignoredIDs, rule.Vulnerability)
					}
				}
				assert.Contains(t, ignoredIDs, "CVE-2022-25883",
					"ignore filters must cover the upstream CVE so the caller can suppress the match")
			}
		})
	}
}

// TestMatchPackageByLanguage_RootIOPyPI verifies the same NAK suppression for rootio PyPI packages.
func TestMatchPackageByLanguage_RootIOPyPI(t *testing.T) {
	// upstream disclosure: CVE affects plain requests
	disclosure := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2025-30473",
			Namespace: "github:language:python",
		},
		PackageName: "requests",
		Constraint:  version.MustGetConstraint("< 2.31.0", version.PythonFormat),
	}

	// rootio NAK: rootio-requests at or above rootio fix is unaffected.
	// PackageName uses the PEP 503 normalized form (hyphen) as stored in the DB.
	// RelatedVulnerabilities bridges the rootio ID to the upstream CVE for Remove().
	nak := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "ROOT-APP-PYPI-CVE-2025-30473",
			Namespace: "github:language:python",
		},
		PackageName: "rootio-requests",
		Constraint:  version.MustGetConstraint(">= 2.31.0+root.io.1", version.PythonFormat),
		Unaffected:  true,
		RelatedVulnerabilities: []vulnerability.Reference{
			{ID: "CVE-2025-30473"},
		},
	}

	tests := []struct {
		name          string
		pkgVersion    string
		vulns         []vulnerability.Vulnerability
		expectMatches int
	}{
		{
			// rootio_requests (underscore) is detected as rootio by hasRootIOPrefix;
			// StripPrefix("rootio_requests", PythonPkg) → "requests", enabling the
			// stripped-name search that finds upstream CVE records.
			name:          "rootio pypi package below fix — disclosure found via stripped name",
			pkgVersion:    "2.28.0",
			vulns:         []vulnerability.Vulnerability{disclosure},
			expectMatches: 1,
		},
		{
			name:          "rootio pypi package at rootio fix — not vulnerable (PEP 440 local version >= upstream fix)",
			pkgVersion:    "2.31.0+root.io.1",
			vulns:         []vulnerability.Vulnerability{disclosure, nak},
			expectMatches: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use underscore form: hasRootIOPrefix checks "rootio_" for PythonPkg.
			// Syft reports PyPI packages with their raw (possibly underscored) name.
			p := pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "rootio_requests",
				Version:  tt.pkgVersion,
				Language: syftPkg.Python,
				Type:     syftPkg.PythonPkg,
			}

			vp := mock.VulnerabilityProvider(tt.vulns...)
			matches, _, err := MatchPackageByLanguage(vp, p, match.PythonMatcher)
			require.NoError(t, err)
			assert.Len(t, matches, tt.expectMatches, "unexpected match count for %q", tt.name)
		})
	}
}
