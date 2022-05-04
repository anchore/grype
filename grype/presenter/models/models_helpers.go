package models

import (
	"testing"

	"github.com/google/uuid"

	grypeDb "github.com/anchore/grype/grype/db/v4"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

func GenerateAnalysis(t *testing.T) (match.Matches, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	packages := generatePackages(t)
	matches := generateMatches(t, packages[0])
	context := generateContext(t)

	return matches, packages, context, NewMetadataMock(), nil, nil
}

func generateMatches(t *testing.T, p pkg.Package) match.Matches {
	t.Helper()

	matches := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-1999-0001",
				Namespace: "source-1",
				Fix: vulnerability.Fix{
					Versions: []string{"the-next-version"},
					State:    grypeDb.FixedState,
				},
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: match.DpkgMatcher,
					SearchedBy: map[string]interface{}{
						"distro": map[string]string{
							"type":    "ubuntu",
							"version": "20.04",
						},
					},
					Found: map[string]interface{}{
						"constraint": ">= 20",
					},
				},
			},
		},
		{

			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-1999-0002",
				Namespace: "source-2",
			},
			Package: p,
			Details: []match.Detail{
				{
					Type:    match.ExactIndirectMatch,
					Matcher: match.DpkgMatcher,
					SearchedBy: map[string]interface{}{
						"cpe": "somecpe",
					},
					Found: map[string]interface{}{
						"constraint": "somecpe",
					},
				},
			},
		},
	}

	collection := match.NewMatches(matches...)

	return collection
}

func generatePackages(t *testing.T) []pkg.Package {
	t.Helper()

	return []pkg.Package{
		{
			ID:        pkg.ID(uuid.NewString()),
			Name:      "package-1",
			Version:   "1.1.1",
			Type:      syftPkg.DebPkg,
			Locations: syftSource.NewLocationSet(syftSource.NewLocation("/somefile-1.txt")),
			CPEs: []syftPkg.CPE{
				{
					Part:     "a",
					Vendor:   "anchore",
					Product:  "engine",
					Version:  "0.9.2",
					Language: "python",
				},
			},
		},
		{
			ID:        pkg.ID(uuid.NewString()),
			Name:      "package-2",
			Version:   "2.2.2",
			Type:      syftPkg.DebPkg,
			Locations: syftSource.NewLocationSet(syftSource.NewLocation("/somefile-2.txt")),
		},
	}
}

func generateContext(t *testing.T) pkg.Context {
	img := image.Image{}

	src, err := syftSource.NewFromImage(&img, "user-input")
	if err != nil {
		t.Fatalf("failed to create scope: %+v", err)
	}

	return pkg.Context{
		Source: &src.Metadata,
		Distro: &linux.Release{
			Name: "centos",
			IDLike: []string{
				"rhel",
			},
			Version: "8.0",
		},
	}
}
