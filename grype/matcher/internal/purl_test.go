package internal

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func newPURLTestStore() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2020-fake-1",
				Namespace: "bitnami",
			},
			PackageName: "apache",
			Constraint:  version.MustGetConstraint("< 1.0.1", version.SemanticFormat),
		},
		// TODO: Add test cases.
	}...)
}

func TestMatchPackageByPURL(t *testing.T) {
	matcher := match.BitnamiMatcher
	tests := []struct {
		name     string
		p        pkg.Package
		expected []match.Match
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name: "match from range",
			p: pkg.Package{
				Name:    "apache",
				Version: "1.0.0",
				Type:    syftPkg.BitnamiPkg,
				PURL:    "pkg:bitnami/apache@1.0.0?arch=arm64&distro=debian-12",
			},
			expected: []match.Match{
				{
					Vulnerability: vulnerability.Vulnerability{
						Reference: vulnerability.Reference{ID: "CVE-2020-fake-1"},
					},
					Package: pkg.Package{
						Name:    "apache",
						Version: "1.0.0",
						Type:    syftPkg.BitnamiPkg,
						PURL:    "pkg:bitnami/apache@1.0.0?arch=arm64&distro=debian-12",
					},
					Details: []match.Detail{{
						Type:       match.PURLMatch,
						Confidence: 0.9,
						SearchedBy: match.PURLParameters{
							Namespace: "bitnami",
							Package: match.PackageParameter{
								Name:    "apache",
								Version: "1.0.0",
							},
							PURL: "pkg:bitnami/apache@1.0.0?arch=arm64&distro=debian-12",
						},
						Found: match.PURLResult{
							VersionConstraint: "< 1.0.1 (semver)",
							VulnerabilityID:   "CVE-2020-fake-1",
							PURL:              "pkg:bitnami/apache@1.0.0?arch=arm64&distro=debian-12",
						},
						Matcher: matcher,
					}},
				},
			},
		},
		// TODO: Add test cases.
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := MatchPackageByPURL(newPURLTestStore(), test.p, matcher)
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
