package internal

import (
	"regexp"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	syftSource "github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/filesource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

const (
	DirectorySource SyftSource = "directory"
	ImageSource     SyftSource = "image"
	FileSource      SyftSource = "file"
)

type SyftSource string

func GenerateAnalysis(t *testing.T, scheme SyftSource) (*sbom.SBOM, match.Matches, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: syftPkg.NewCollection(generatePackages(t)...),
		},
	}

	grypePackages := pkg.FromCollection(s.Artifacts.Packages, pkg.SynthesisConfig{})

	matches := generateMatches(t, grypePackages[0], grypePackages[1])
	context := generateContext(t, scheme)

	return s, matches, grypePackages, context, models.NewMetadataMock(), nil, nil
}

func GenerateAnalysisWithIgnoredMatches(t *testing.T, scheme SyftSource) (match.Matches, []match.IgnoredMatch, []pkg.Package, pkg.Context, vulnerability.MetadataProvider, interface{}, interface{}) {
	t.Helper()

	s := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: syftPkg.NewCollection(generatePackages(t)...),
		},
	}

	grypePackages := pkg.FromCollection(s.Artifacts.Packages, pkg.SynthesisConfig{})

	matches := generateMatches(t, grypePackages[0], grypePackages[1])
	ignoredMatches := generateIgnoredMatches(t, grypePackages[1])
	context := generateContext(t, scheme)

	return matches, ignoredMatches, grypePackages, context, models.NewMetadataMock(), nil, nil
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

func generateMatches(t *testing.T, p1, p2 pkg.Package) match.Matches {
	t.Helper()

	matches := []match.Match{
		{

			Vulnerability: vulnerability.Vulnerability{
				Reference: vulnerability.Reference{
					ID:        "CVE-1999-0001",
					Namespace: "source-1",
				},
				Fix: vulnerability.Fix{
					Versions: []string{"the-next-version"},
					State:    vulnerability.FixStateFixed,
				},
			},
			Package: p1,
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
				Reference: vulnerability.Reference{
					ID:        "CVE-1999-0002",
					Namespace: "source-2",
				},
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

// nolint: funlen
func generateIgnoredMatches(t *testing.T, p pkg.Package) []match.IgnoredMatch {
	t.Helper()

	return []match.IgnoredMatch{
		{
			Match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-1999-0001",
						Namespace: "source-1",
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
			AppliedIgnoreRules: []match.IgnoreRule{},
		},
		{
			Match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-1999-0002",
						Namespace: "source-2",
					},
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
			AppliedIgnoreRules: []match.IgnoreRule{},
		},
		{
			Match: match.Match{
				Vulnerability: vulnerability.Vulnerability{
					Reference: vulnerability.Reference{
						ID:        "CVE-1999-0004",
						Namespace: "source-2",
					},
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
			AppliedIgnoreRules: []match.IgnoreRule{
				{
					Vulnerability:    "CVE-1999-0004",
					Namespace:        "vex",
					Package:          match.IgnoreRulePackage{},
					VexStatus:        string(vex.StatusNotAffected),
					VexJustification: "this isn't the vulnerability match you're looking for... *waves hand*",
				},
			},
		},
	}
}

func generatePackages(t *testing.T) []syftPkg.Package {
	t.Helper()
	epoch := 2

	pkgs := []syftPkg.Package{
		{
			Name:      "package-1",
			Version:   "1.1.1",
			Type:      syftPkg.RpmPkg,
			Locations: file.NewLocationSet(file.NewVirtualLocation("/foo/bar/somefile-1.txt", "somefile-1.txt")),
			CPEs: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:     "a",
						Vendor:   "anchore",
						Product:  "engine",
						Version:  "0.9.2",
						Language: "python",
					},
				},
			},
			Metadata: syftPkg.RpmDBEntry{
				Epoch:     &epoch,
				SourceRpm: "some-source-rpm",
			},
		},
		{
			Name:      "package-2",
			Version:   "2.2.2",
			Type:      syftPkg.DebPkg,
			PURL:      "pkg:deb/package-2@2.2.2",
			Locations: file.NewLocationSet(file.NewVirtualLocation("/foo/bar/somefile-2.txt", "somefile-2.txt")),
			CPEs: []cpe.CPE{
				{
					Attributes: cpe.Attributes{
						Part:     "a",
						Vendor:   "anchore",
						Product:  "engine",
						Version:  "2.2.2",
						Language: "python",
					},
				},
			},
			Licenses: syftPkg.NewLicenseSet(
				syftPkg.NewLicense("MIT"),
				syftPkg.NewLicense("Apache-2.0"),
			),
		},
	}

	for i := range pkgs {
		p := pkgs[i]
		p.SetID()
	}

	return pkgs
}

//nolint:funlen
func generateContext(t *testing.T, scheme SyftSource) pkg.Context {
	var (
		src  syftSource.Source
		desc syftSource.Description
	)

	switch scheme {
	case FileSource:
		var err error
		src, err = filesource.NewFromPath("user-input")
		if err != nil {
			t.Fatalf("failed to generate mock file source from mock image: %+v", err)
		}
		desc = src.Describe()
	case ImageSource:
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

		src = stereoscopesource.New(&img, stereoscopesource.ImageConfig{
			Reference: "user-input",
		})
		desc = src.Describe()
	case DirectorySource:
		// note: the dir must exist for the source to be created
		d := t.TempDir()
		var err error
		src, err = directorysource.NewFromPath(d)

		if err != nil {
			t.Fatalf("failed to generate mock directory source from mock dir: %+v", err)
		}
		desc = src.Describe()
		if m, ok := desc.Metadata.(syftSource.DirectoryMetadata); ok {
			m.Path = "/some/path"
			desc.Metadata = m
		}
	default:
		t.Fatalf("unknown scheme: %s", scheme)
	}

	return pkg.Context{
		Source: &desc,
		Distro: &linux.Release{
			Name: "centos",
			IDLike: []string{
				"centos",
			},
			Version: "8.0",
		},
	}
}
