package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/linux"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	var testImage = "image-simple"

	if *update {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	img := imagetest.GetGoldenFixtureImage(t, testImage)

	getImageLocation := func(filepath string) syftSource.Location {
		_, ref, _ := img.SquashedTree().File(file.Path(filepath))
		return syftSource.NewLocationFromImage("", *ref, img)
	}

	epoch := 2

	var pkg1 = pkg.Package{
		ID:      pkg.ID("package-1-id"),
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.RpmPkg,
		Locations: syftSource.NewLocationSet(
			getImageLocation("/somefile-1.txt"),
		),
		CPEs: []syftPkg.CPE{
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
		MetadataType: pkg.RpmdbMetadataType,
		Metadata:     pkg.RpmdbMetadata{Epoch: &epoch},
	}

	var pkg2 = pkg.Package{
		ID:      pkg.ID("package-2-id"),
		Name:    "package-2",
		Version: "2.2.2",
		Type:    syftPkg.DebPkg,
		Locations: syftSource.NewLocationSet(
			getImageLocation("/somefile-2.txt"),
		),
	}

	var match1 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0001",
			Namespace: "source-1",
			Fix: vulnerability.Fix{
				Versions: []string{
					"the-next-versions",
				},
			},
		},
		Package: pkg1,
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
	}

	var match2 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0002",
			Namespace: "source-2",
		},
		Package: pkg1,
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
	}

	var match3 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0003",
			Namespace: "source-1",
			Fix: vulnerability.Fix{
				Versions: []string{
					"the-other-next-version",
				},
			},
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactIndirectMatch,
				Matcher: match.DpkgMatcher,
				SearchedBy: map[string]interface{}{
					"language": "java",
				},
				Found: map[string]interface{}{
					"constraint": "< 2.0.0",
				},
			},
		},
	}

	matches := match.NewMatches()
	matches.Add(match1, match2, match3)

	packages := []pkg.Package{pkg1, pkg2}

	src, err := syftSource.NewFromImage(img, "user-input")
	if err != nil {
		t.Fatalf("failed to create scope: %+v", err)
	}

	ctx := pkg.Context{
		Source: &src.Metadata,
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}
	pres := NewPresenter(matches, nil, packages, ctx, models.NewMetadataMock(), nil, nil)

	// TODO: add a constructor for a match.Match when the data is better shaped

	// run presenter
	if err = pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := syftPkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(syftPkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
		FoundBy: "the-cataloger-1",
		Locations: syftSource.NewLocationSet(
			syftSource.NewLocation("/some/path/pkg1"),
		),
	})

	var pkg1 pkg.Package

	// we need a package with an ID from the catalog (we should fix this)
	// TODO: fix this
	for p := range catalog.Enumerate() {
		pkg1 = pkg.New(p)
		break
	}

	var match1 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0001",
			Namespace: "source-1",
			Fix: vulnerability.Fix{
				Versions: []string{
					"the-next-version",
				},
			},
		},
		Package: pkg1,
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
	}

	var match2 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0002",
			Namespace: "source-2",
		},
		Package: pkg1,
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
	}

	var match3 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0003",
			Namespace: "source-1",
			Fix: vulnerability.Fix{
				Versions: []string{
					"the-other-next-version",
				},
			},
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactIndirectMatch,
				Matcher: match.DpkgMatcher,
				SearchedBy: map[string]interface{}{
					"language": "java",
				},
				Found: map[string]interface{}{
					"constraint": "< 2.0.0",
				},
			},
		},
	}

	matches := match.NewMatches()
	matches.Add(match1, match2, match3)

	s, err := syftSource.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatal(err)
	}

	ctx := pkg.Context{
		Source: &s.Metadata,
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}
	pres := NewPresenter(matches, nil, pkg.FromCatalog(catalog, pkg.ProviderConfig{}), ctx, models.NewMetadataMock(), nil, nil)

	// TODO: add a constructor for a match.Match when the data is better shaped

	// run presenter
	if err = pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// Expected to have an empty JSON array back
	var buffer bytes.Buffer

	var testImage = "image-simple"

	if *update {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	img := imagetest.GetGoldenFixtureImage(t, testImage)

	matches := match.NewMatches()

	src, err := syftSource.NewFromImage(img, "user-input")
	if err != nil {
		t.Fatalf("failed to create scope: %+v", err)
	}

	ctx := pkg.Context{
		Source: &src.Metadata,
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	pres := NewPresenter(matches, nil, []pkg.Package{}, ctx, nil, nil, nil)

	// run presenter
	if err = pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))
}
