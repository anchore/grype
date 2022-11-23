package models

import (
	"regexp"
	"testing"

	"github.com/google/uuid"

	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

func GenerateAnalysis(t *testing.T, scheme syftSource.Scheme) (match.Matches, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	packages := generatePackages(t)
	matches := generateMatches(t, packages[0], packages[1])
	context := generateContext(t, scheme)

	return matches, packages, context, NewMetadataMock(), nil, nil
}

func Redact(s []byte) []byte {
	serialPattern := regexp.MustCompile(`serialNumber="[a-zA-Z0-9\-:]+"`)
	uuidPattern := regexp.MustCompile(`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	refPattern := regexp.MustCompile(`ref="[a-zA-Z0-9\-:]+"`)
	rfc3339Pattern := regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`)
	cycloneDxBomRefPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	for _, pattern := range []*regexp.Regexp{serialPattern, rfc3339Pattern, refPattern, uuidPattern, cycloneDxBomRefPattern} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
}

func generateMatches(t *testing.T, p, p2 pkg.Package) match.Matches {
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
			Package: p2,
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
			Locations: syftSource.NewLocationSet(syftSource.NewVirtualLocation("/foo/bar/somefile-1.txt", "somefile-1.txt")),
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
			Locations: syftSource.NewLocationSet(syftSource.NewVirtualLocation("/foo/bar/somefile-2.txt", "somefile-2.txt")),
		},
	}
}

func generateContext(t *testing.T, scheme syftSource.Scheme) pkg.Context {
	var src syftSource.Source
	img := image.Image{}

	switch scheme {
	case syftSource.ImageScheme:
		var err error
		src, err = syftSource.NewFromImage(&img, "user-input")
		if err != nil {
			t.Fatalf("failed to generate mock image source from mock image: %+v", err)
		}
	case syftSource.DirectoryScheme:
		var err error
		src, err = syftSource.NewFromDirectory("/some/path")
		if err != nil {
			t.Fatalf("failed to generate mock directory source from mock dir: %+v", err)
		}
	default:
		t.Fatalf("unknown scheme: %s", scheme)
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
