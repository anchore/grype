package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/scope"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
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

func TestJsonPresenter(t *testing.T) {
	var buffer bytes.Buffer
	var testImage = "image-simple"

	if *update {
		testutils.UpdateGoldenFixtureImage(t, testImage)
	}

	img := testutils.GetGoldenFixtureImage(t, testImage)

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.DebPkg,
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-1.txt"),
		},
		FoundBy: "the-cataloger-1",
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-2.txt"),
		},
		FoundBy: "the-cataloger-2",
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0001",
			RecordSource:   "source-1",
			FixedInVersion: "the-next-version",
		},
		Package: &pkg1,
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
		Package: &pkg1,
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
		Package: &pkg1,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"language": "java",
		},
		SearchMatches: map[string]interface{}{
			"constraint": "< 2.0.0",
		},
	}

	results := match.NewResult()
	results.Add(&pkg1, match1, match2, match3)

	catalog := pkg.NewCatalog()
	catalog.Add(pkg1)
	catalog.Add(pkg2)

	theScope, err := scope.NewScopeFromImage(img, scope.AllLayersScope)

	pres := NewPresenter(results, catalog, theScope, newMetadataMock())

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

	results := match.NewResult()

	catalog := pkg.NewCatalog()

	pres := NewPresenter(results, catalog, scope.Scope{}, nil)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
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
