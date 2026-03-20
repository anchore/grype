package internal

import (
	"testing"

	"github.com/google/uuid"
	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func newMockProviderByDistro() vulnerability.Provider {
	return mock.VulnerabilityProvider([]vulnerability.Vulnerability{
		{
			// direct...
			PackageName: "neutron",
			Constraint:  version.MustGetConstraint("< 2014.1.5-6", version.DebFormat),
			Reference: vulnerability.Reference{
				ID:        "CVE-2014-fake-1",
				Namespace: "secdb:distro:debian:8",
			},
		},
		{
			PackageName: "sles_test_package",
			Constraint:  version.MustGetConstraint("< 2014.1.5-6", version.RpmFormat),
			Reference: vulnerability.Reference{
				ID:        "CVE-2014-fake-4",
				Namespace: "secdb:distro:sles:12.5",
			},
		},
	}...)
}

func TestFindMatchesByPackageDistro(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.DebPkg,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "neutron-devel",
			},
		},
	}

	d := distro.New(distro.Debian, "8", "")
	p.Distro = d

	expected := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2014-fake-1",
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    "debian",
							Version: "8",
						},
						Package: match.PackageParameter{
							Name:    "neutron",
							Version: "2014.1.3-6",
						},
						Namespace: "secdb:distro:debian:8",
					},
					Found: match.DistroResult{
						VersionConstraint: "< 2014.1.5-6 (deb)",
						VulnerabilityID:   "CVE-2014-fake-1",
					},
					Matcher: match.PythonMatcher,
				},
			},
		},
	}

	store := newMockProviderByDistro()
	actual, ignored, err := MatchPackageByDistro(store, p, nil, match.PythonMatcher, nil)
	require.NoError(t, err)
	require.Empty(t, ignored)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)

	// prove we do not search for unknown versions
	p.Version = "unknown"
	actual, ignored, err = MatchPackageByDistro(store, p, nil, match.PythonMatcher, nil)
	require.NoError(t, err)
	require.Empty(t, ignored)
	assert.Empty(t, actual)
}

func TestMatchPackageByDistroWithIgnoreRules(t *testing.T) {
	ownedFiles := pkg.ApkMetadata{Files: []pkg.ApkFileRecord{
		{Path: "/usr/lib/python3/dist-packages/requests"},
		{Path: "/usr/bin/python3"},
	}}

	tests := []struct {
		name                  string
		pkg                   pkg.Package
		vulnerabilities       []vulnerability.Vulnerability
		expectedIgnoreVulnIDs []string
		expectedMatchIDs      []string
		expectNoIgnoreRules   bool
	}{
		{
			name: "package version is already fixed - should produce ignore rules scoped to paths",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "2.25.1-14.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-backported", Namespace: "secdb:distro:redhat:8"},
				},
			},
			// one rule per (vulnID, path) pair
			expectedIgnoreVulnIDs: []string{"CVE-2023-backported"},
		},
		{
			name: "package version is still vulnerable - should NOT produce ignore rules",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "2.25.1-10.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-backported", Namespace: "secdb:distro:redhat:8"},
				},
			},
			expectedMatchIDs:    []string{"CVE-2023-backported"},
			expectNoIgnoreRules: true,
		},
		{
			name: "distro has no data about the package - should NOT produce ignore rules (search miss)",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-something-obscure",
				Version:  "1.0.0-1.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				// no vulnerabilities for this package in the distro feed
				{
					PackageName: "other-package",
					Constraint:  version.MustGetConstraint("< 2.0.0", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-other", Namespace: "secdb:distro:redhat:8"},
				},
			},
			expectNoIgnoreRules: true,
		},
		{
			name: "mix of fixed and still-vulnerable CVEs - should only produce ignore rules for fixed ones",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "2.25.1-14.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					// fixed: package version 2.25.1-14.el8 >= fix version
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-already-fixed", Namespace: "secdb:distro:redhat:8"},
				},
				{
					// still vulnerable: package version 2.25.1-14.el8 < 2.25.1-20.el8
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-20.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-still-vulnerable", Namespace: "secdb:distro:redhat:8"},
				},
			},
			expectedMatchIDs: []string{"CVE-2023-still-vulnerable"},
			// one rule per path for the fixed CVE only
			expectedIgnoreVulnIDs: []string{"CVE-2023-already-fixed"},
		},
		{
			name: "fixed CVE with related vulnerabilities - should produce ignore rules for all IDs at all paths",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "2.25.1-14.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-backported", Namespace: "secdb:distro:redhat:8"},
					RelatedVulnerabilities: []vulnerability.Reference{
						{ID: "GHSA-xxxx-yyyy-zzzz", Namespace: "github:language:python"},
					},
				},
			},
			// both IDs × 2 paths = 4 rules
			expectedIgnoreVulnIDs: []string{"CVE-2023-backported", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			name: "no distro on package - should NOT produce ignore rules",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "2.25.1-14.el8",
				Type:     syftPkg.RpmPkg,
				Distro:   nil,
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-backported", Namespace: "secdb:distro:redhat:8"},
				},
			},
			expectNoIgnoreRules: true,
		},
		{
			name: "unknown version - should NOT produce ignore rules",
			pkg: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "python3-requests",
				Version:  "unknown",
				Type:     syftPkg.RpmPkg,
				Distro:   distro.New(distro.RedHat, "8", ""),
				Metadata: ownedFiles,
			},
			vulnerabilities: []vulnerability.Vulnerability{
				{
					PackageName: "python3-requests",
					Constraint:  version.MustGetConstraint("< 2.25.1-14.el8", version.RpmFormat),
					Reference:   vulnerability.Reference{ID: "CVE-2023-backported", Namespace: "secdb:distro:redhat:8"},
				},
			},
			expectNoIgnoreRules: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := mock.VulnerabilityProvider(test.vulnerabilities...)

			matches, ignoreFilters, err := MatchPackageByDistroWithOwnedFiles(store, test.pkg, nil, match.PythonMatcher, nil)
			require.NoError(t, err)

			// verify matches
			var gotMatchIDs []string
			for _, m := range matches {
				gotMatchIDs = append(gotMatchIDs, m.Vulnerability.ID)
			}
			if len(test.expectedMatchIDs) > 0 {
				assert.ElementsMatch(t, test.expectedMatchIDs, gotMatchIDs, "unexpected match IDs")
			}

			if test.expectNoIgnoreRules {
				assert.Empty(t, ignoreFilters, "expected no ignore rules")
				return
			}

			// extract the vulnerability IDs from the ignore rules
			gotVulnIDs := strset.New()
			for _, filter := range ignoreFilters {
				related, ok := filter.(match.IgnoreRelatedPackage)
				if ok {
					gotVulnIDs.Add(related.VulnerabilityID)
					continue
				}
				rule, ok := filter.(match.IgnoreRule)
				require.True(t, ok, "expected IgnoreRule or IgnoreRelatedPackage types")
				gotVulnIDs.Add(rule.Vulnerability)
				assert.True(t, rule.IncludeAliases, "expected IncludeAliases to be true")
				assert.Contains(t, rule.Reason, "DistroPackageFixed")
				assert.NotEmpty(t, rule.Package.Location, "expected location to be set")
			}

			assert.ElementsMatch(t, test.expectedIgnoreVulnIDs, gotVulnIDs.List(), "unexpected ignore rule vulnerability IDs")
		})
	}
}

func TestFindMatchesByPackageDistroSles(t *testing.T) {
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "sles_test_package",
		Version: "2014.1.3-6",
		Type:    syftPkg.RpmPkg,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "sles_test_package",
			},
		},
	}

	d := distro.New(distro.SLES, "12.5", "")
	p.Distro = d

	expected := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID: "CVE-2014-fake-4",
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    "sles",
							Version: "12.5",
						},
						Package: match.PackageParameter{
							Name:    "sles_test_package",
							Version: "2014.1.3-6",
						},
						Namespace: "secdb:distro:sles:12.5",
					},
					Found: match.DistroResult{
						VersionConstraint: "< 2014.1.5-6 (rpm)",
						VulnerabilityID:   "CVE-2014-fake-4",
					},
					Matcher: match.PythonMatcher,
				},
			},
		},
	}

	store := newMockProviderByDistro()
	actual, ignored, err := MatchPackageByDistro(store, p, nil, match.PythonMatcher, nil)
	assert.NoError(t, err)
	require.Empty(t, ignored)
	assertMatchesUsingIDsForVulnerabilities(t, expected, actual)
}
