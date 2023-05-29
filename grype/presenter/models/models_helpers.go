package models

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	grypeDb "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	syftSource "github.com/anchore/syft/syft/source"
)

func GenerateAnalysis(t *testing.T, scheme syftSource.Scheme) (match.Matches, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	packages := generatePackages(t)
	matches := generateMatches(t, packages[0], packages[1])
	context := generateContext(t, scheme)

	return matches, packages, context, NewMetadataMock(), nil, nil
}

func GenerateAnalysisWithIgnoredMatches(t *testing.T, scheme syftSource.Scheme) (match.Matches, []match.IgnoredMatch, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	packages := generatePackages(t)
	matches := generateMatches(t, packages[0], packages[0])
	ignoredMatches := generateIgnoredMatches(t, packages[1])
	context := generateContext(t, scheme)

	return matches, ignoredMatches, packages, context, NewMetadataMock(), nil, nil
}

func SBOMFromPackages(t *testing.T, packages []pkg.Package) *sbom.SBOM {
	t.Helper()

	sbom := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: syftPkg.NewCollection(),
		},
	}

	for _, p := range packages {
		sbom.Artifacts.Packages.Add(toSyftPkg(p))
	}

	return sbom
}

func toSyftPkg(p pkg.Package) syftPkg.Package {
	return syftPkg.Package{
		Name:      p.Name,
		Version:   p.Version,
		Type:      p.Type,
		Metadata:  p.Metadata,
		Locations: p.Locations,
		CPEs:      p.CPEs,
	}
}

func Redact(s []byte) []byte {
	serialPattern := regexp.MustCompile(`serialNumber="[a-zA-Z0-9\-:]+"`)
	uuidPattern := regexp.MustCompile(`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	refPattern := regexp.MustCompile(`ref="[a-zA-Z0-9\-:]+"`)
	rfc3339Pattern := regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`)
	cycloneDxBomRefPattern := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	for _, pattern := range []*regexp.Regexp{serialPattern, rfc3339Pattern, refPattern, uuidPattern, cycloneDxBomRefPattern} {
		s = pattern.ReplaceAll(s, []byte(""))
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

func generateIgnoredMatches(t *testing.T, p pkg.Package) []match.IgnoredMatch {
	t.Helper()

	matches := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				ID:        "CVE-1999-0001",
				Namespace: "source-1",
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
					Type:    match.ExactDirectMatch,
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

	var ignoredMatches []match.IgnoredMatch
	for _, m := range matches {
		ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
			Match:              m,
			AppliedIgnoreRules: []match.IgnoreRule{},
		})
	}

	return ignoredMatches
}

func generatePackages(t *testing.T) []pkg.Package {
	t.Helper()
	epoch := 2

	pkgs := []pkg.Package{
		{
			Name:      "package-1",
			Version:   "1.1.1",
			Type:      syftPkg.RpmPkg,
			Locations: syftSource.NewLocationSet(syftSource.NewVirtualLocation("/foo/bar/somefile-1.txt", "somefile-1.txt")),
			CPEs: []cpe.CPE{
				{
					Part:     "a",
					Vendor:   "anchore",
					Product:  "engine",
					Version:  "0.9.2",
					Language: "python",
				},
			},
			Upstreams: []pkg.UpstreamPackage{
				{
					Name:    "nothing",
					Version: "3.2",
				},
			},
			MetadataType: pkg.RpmMetadataType,
			Metadata: pkg.RpmMetadata{
				Epoch: &epoch,
			},
		},
		{
			Name:      "package-2",
			Version:   "2.2.2",
			Type:      syftPkg.DebPkg,
			Locations: syftSource.NewLocationSet(syftSource.NewVirtualLocation("/foo/bar/somefile-2.txt", "somefile-2.txt")),
			CPEs: []cpe.CPE{
				{
					Part:     "a",
					Vendor:   "anchore",
					Product:  "engine",
					Version:  "2.2.2",
					Language: "python",
				},
			},
			Licenses: []string{"MIT", "Apache-2.0"},
		},
	}

	updatedPkgs := make([]pkg.Package, 0, len(pkgs))

	for _, p := range pkgs {
		id, err := artifact.IDByHash(p)
		require.NoError(t, err)

		p.ID = pkg.ID(id)
		updatedPkgs = append(updatedPkgs, p)
	}

	return updatedPkgs
}

func generateContext(t *testing.T, scheme syftSource.Scheme) pkg.Context {
	var src syftSource.Source
	img := image.Image{
		Metadata: image.Metadata{
			ID:             "sha256:ab5608d634db2716a297adbfa6a5dd5d8f8f5a7d0cab73649ea7fbb8c8da544f",
			ManifestDigest: "sha256:ca738abb87a8d58f112d3400ebb079b61ceae7dc290beb34bda735be4b1941d5",
			MediaType:      "application/vnd.docker.distribution.manifest.v2+json",
			Size:           65,
		},
		Layers: []*image.Layer{
			{
				Metadata: image.LayerMetadata{
					Digest:    "sha256:ca738abb87a8d58f112d3400ebb079b61ceae7dc290beb34bda735be4b1941d5",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Size:      22,
				},
			},
			{
				Metadata: image.LayerMetadata{
					Digest:    "sha256:a05cd9ebf88af96450f1e25367281ab232ac0645f314124fe01af759b93f3006",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Size:      16,
				},
			},
			{
				Metadata: image.LayerMetadata{
					Digest:    "sha256:ab5608d634db2716a297adbfa6a5dd5d8f8f5a7d0cab73649ea7fbb8c8da544f",
					MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
					Size:      27,
				},
			},
		},
	}

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
				"centos",
			},
			Version: "8.0",
		},
	}
}
