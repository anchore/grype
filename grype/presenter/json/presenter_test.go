package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/distro"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

type metadataMock struct {
	store map[string]map[string]vulnerability.Metadata
}

func newMetadataMock() *metadataMock {
	return &metadataMock{
		store: map[string]map[string]vulnerability.Metadata{
			"CVE-1999-0001": {
				"source-1": {
					Description: "1999-01 description",
					CvssV3: &vulnerability.Cvss{
						BaseScore: 4,
						Vector:    "another vector",
					},
				},
			},
			"CVE-1999-0002": {
				"source-2": {
					Description: "1999-02 description",
					CvssV2: &vulnerability.Cvss{
						BaseScore:           1,
						ExploitabilityScore: 2,
						ImpactScore:         3,
						Vector:              "vector",
					},
				},
			},
			"CVE-1999-0003": {
				"source-1": {
					Description: "1999-03 description",
				},
			},
		},
	}
}

func (m *metadataMock) GetMetadata(id, recordSource string) (*vulnerability.Metadata, error) {
	value := m.store[id][recordSource]
	return &value, nil
}

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	var testImage = "image-simple"

	if *update {
		imagetest.UpdateGoldenFixtureImage(t, testImage)
	}

	img := imagetest.GetGoldenFixtureImage(t, testImage)

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.1.1",
		Type:    syftPkg.DebPkg,
		Locations: []source.Location{
			source.NewLocationFromImage(*img.SquashedTree().File("/somefile-1.txt"), img),
		},
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.2.2",
		Type:    syftPkg.DebPkg,
		Locations: []source.Location{
			source.NewLocationFromImage(*img.SquashedTree().File("/somefile-2.txt"), img),
		},
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0001",
			RecordSource:   "source-1",
			FixedInVersion: "the-next-version",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"distro": map[string]string{
				"type":    "ubuntu",
				"version": "20.04",
			},
		},
		SearchMatches: map[string]interface{}{
			"constraint": ">= 20",
		},
	}

	var match2 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-1999-0002",
			RecordSource: "source-2",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"cpe": "somecpe",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "somecpe",
		},
	}

	var match3 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0003",
			RecordSource:   "source-1",
			FixedInVersion: "the-other-next-version",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"language": "java",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "< 2.0.0",
		},
	}

	d, err := distro.NewDistro(distro.CentOS, "8.0", "rhel")
	if err != nil {
		t.Fatalf("could not make distro: %+v", err)
	}

	matches := match.NewMatches()
	matches.Add(pkg1, match1, match2, match3)

	packages := []pkg.Package{pkg1, pkg2}

	theSource, err := source.NewFromImage(img, source.AllLayersScope, "user-input")
	if err != nil {
		t.Fatalf("failed to create scope: %+v", err)
	}

	pres := NewPresenter(matches, packages, &d, theSource.Metadata, newMetadataMock())

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

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstV1Schema(t, string(actual))
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
		Locations: []source.Location{
			{Path: "/some/path/pkg1"},
		},
	})

	var pkg1 pkg.Package

	// we need a package with an ID from the catalog (we should fix this)
	// TODO: fix this
	for p := range catalog.Enumerate() {
		pkg1 = pkg.New(p)
		break
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0001",
			RecordSource:   "source-1",
			FixedInVersion: "the-next-version",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"distro": map[string]string{
				"type":    "ubuntu",
				"version": "20.04",
			},
		},
		SearchMatches: map[string]interface{}{
			"constraint": ">= 20",
		},
	}

	var match2 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-1999-0002",
			RecordSource: "source-2",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"cpe": "somecpe",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "somecpe",
		},
	}

	var match3 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0003",
			RecordSource:   "source-1",
			FixedInVersion: "the-other-next-version",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"language": "java",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "< 2.0.0",
		},
	}

	matches := match.NewMatches()
	matches.Add(pkg1, match1, match2, match3)

	s, err := source.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatal(err)
	}

	d, err := distro.NewDistro(distro.CentOS, "8.0", "rhel")
	if err != nil {
		t.Fatalf("could not make distro: %+v", err)
	}

	pres := NewPresenter(matches, pkg.FromCatalog(catalog), &d, s.Metadata, newMetadataMock())

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

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstV1Schema(t, string(actual))
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

	theSource, err := source.NewFromImage(img, source.AllLayersScope, "user-input")
	if err != nil {
		t.Fatalf("failed to create scope: %+v", err)
	}

	d, err := distro.NewDistro(distro.CentOS, "8.0", "rhel")
	if err != nil {
		t.Fatalf("could not make distro: %+v", err)
	}

	pres := NewPresenter(matches, []pkg.Package{}, &d, theSource.Metadata, nil)

	// run presenter
	if err = pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}
