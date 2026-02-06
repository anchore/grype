package internal

import (
	"testing"

	"github.com/google/uuid"
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
