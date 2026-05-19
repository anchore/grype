package pacman

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestMatcherType(t *testing.T) {
	m := Matcher{}
	assert.Equal(t, match.PacmanMatcher, m.Type())
}

func TestMatcherPackageTypes(t *testing.T) {
	m := Matcher{}
	assert.Equal(t, []syftPkg.Type{syftPkg.AlpmPkg}, m.PackageTypes())
}

func TestMatch(t *testing.T) {
	archVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "AVG-1234",
			Namespace: "arch:distro:archlinux:rolling",
		},
		PackageName: "curl",
		Constraint:  version.MustGetConstraint("< 8.5.0-1", version.PacmanFormat),
	}

	vp := mock.VulnerabilityProvider(archVuln)

	m := Matcher{}
	d := distro.New(distro.ArchLinux, "", "rolling")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "curl",
		Version: "8.4.0-1",
		Type:    syftPkg.AlpmPkg,
		Distro:  d,
	}

	expected := []match.Match{
		{
			Vulnerability: archVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    d.Type.String(),
							Version: d.Version,
						},
						Package: match.PackageParameter{
							Name:    "curl",
							Version: "8.4.0-1",
						},
						Namespace: "arch:distro:archlinux:rolling",
					},
					Found: match.DistroResult{
						VulnerabilityID:   "AVG-1234",
						VersionConstraint: archVuln.Constraint.String(),
					},
					Matcher: match.PacmanMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestMatchNoVulnerability(t *testing.T) {
	archVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "AVG-1234",
			Namespace: "arch:distro:archlinux:rolling",
		},
		PackageName: "curl",
		Constraint:  version.MustGetConstraint("< 8.0.0-1", version.PacmanFormat),
	}

	vp := mock.VulnerabilityProvider(archVuln)

	m := Matcher{}
	d := distro.New(distro.ArchLinux, "", "rolling")

	// Package version is newer than the constraint, should not match
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "curl",
		Version: "8.5.0-1",
		Type:    syftPkg.AlpmPkg,
		Distro:  d,
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)
	assert.Empty(t, actual)
}

func TestMatchWithEpoch(t *testing.T) {
	archVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "AVG-5678",
			Namespace: "arch:distro:archlinux:rolling",
		},
		PackageName: "openssl",
		Constraint:  version.MustGetConstraint("< 1:3.0.8-1", version.PacmanFormat),
	}

	vp := mock.VulnerabilityProvider(archVuln)

	m := Matcher{}
	d := distro.New(distro.ArchLinux, "", "rolling")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "openssl",
		Version: "1:3.0.7-4",
		Type:    syftPkg.AlpmPkg,
		Distro:  d,
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)
	require.Len(t, actual, 1)
	assert.Equal(t, "AVG-5678", actual[0].Vulnerability.ID)
}

func TestMatchNilDistro(t *testing.T) {
	m := Matcher{}

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "curl",
		Version: "8.4.0-1",
		Type:    syftPkg.AlpmPkg,
		Distro:  nil,
	}

	actual, _, err := m.Match(mock.VulnerabilityProvider(), p)
	require.NoError(t, err)
	assert.Empty(t, actual)
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	opts := []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
		cmpopts.IgnoreUnexported(distro.Distro{}),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
