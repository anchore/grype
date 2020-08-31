package cyclonedx

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/result"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
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
					Severity:    "Low",
					CvssV3: &vulnerability.Cvss{
						BaseScore: 4,
						Vector:    "another vector",
					},
				},
			},
			"CVE-1999-0002": {
				"source-2": {
					Description: "1999-02 description",
					Severity:    "Critical",
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
					Severity:    "High",
				},
			},
		},
	}
}

func (m *metadataMock) GetMetadata(id, recordSource string) (*vulnerability.Metadata, error) {
	value := m.store[id][recordSource]
	return &value, nil
}

func TestCycloneDxImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	catalog := pkg.NewCatalog()
	img, cleanup := testutils.GetFixtureImage(t, "docker-archive", "image-simple")
	defer cleanup()

	// populate catalog with test data
	catalog.Add(pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-1.txt"),
		},
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-1",
	})
	catalog.Add(pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Source: []file.Reference{
			*img.SquashedTree().File("/somefile-2.txt"),
		},
		Type:    pkg.DebPkg,
		FoundBy: "the-cataloger-2",
		Licenses: []string{
			"MIT",
			"Apache-v2",
		},
	})

	s, err := scope.NewScopeFromImage(img, scope.AllLayersScope)

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-1999-0001",
			RecordSource: "source-1",
		},
		Package: &pkg1,
		Matcher: match.DpkgMatcher,
	}

	var match2 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-1999-0002",
			RecordSource: "source-2",
		},
		Package:   &pkg2,
		Matcher:   match.DpkgMatcher,
		SearchKey: "a search key...",
	}

	results := result.NewResult()

	results.Add(&pkg1, match1, match2)

	pres := NewPresenter(results, catalog, s, newMetadataMock())

	// run presenter
	err = pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(actual), string(expected), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func redact(s []byte) []byte {
	serialPattern := regexp.MustCompile(`serialNumber="[a-zA-Z0-9\-:]+"`)
	refPattern := regexp.MustCompile(`ref="[a-zA-Z0-9\-:]+"`)
	rfc3339Pattern := regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`)

	for _, pattern := range []*regexp.Regexp{serialPattern, rfc3339Pattern, refPattern} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
}
