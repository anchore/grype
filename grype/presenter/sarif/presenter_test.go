package sarif

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/imagetest"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", true, "update the *.golden files for json presenters")

func createResults() (match.Matches, []pkg.Package) {

	pkg1 := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
		Locations: []source.Location{
			{
				Coordinates: source.Coordinates{
					RealPath:     "etc/pkg-1",
					FileSystemID: "sha256:asdf",
				},
			},
		},
	}
	pkg2 := pkg.Package{
		ID:      "package-2-id",
		Name:    "package-2",
		Version: "2.0.1",
		Type:    syftPkg.DebPkg,
		Licenses: []string{
			"MIT",
			"Apache-v2",
		},
		Locations: []source.Location{
			{
				Coordinates: source.Coordinates{
					RealPath:     "pkg-2",
					FileSystemID: "sha256:asdf",
				},
			},
		},
	}

	var match1 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0001",
			Namespace: "source-1",
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactDirectMatch,
				Matcher: match.DpkgMatcher,
			},
		},
	}

	var match2 = match.Match{

		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0002",
			Namespace: "source-2",
		},
		Package: pkg2,
		Details: []match.Detail{
			{
				Type:    match.ExactIndirectMatch,
				Matcher: match.DpkgMatcher,
				SearchedBy: map[string]interface{}{
					"some": "key",
				},
			},
		},
	}

	matches := match.NewMatches()

	matches.Add(match1, match2)

	return matches, []pkg.Package{pkg1, pkg2}
}

func createImagePresenter(t *testing.T) *Presenter {
	matches, packages := createResults()

	img := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")
	s, err := source.NewFromImage(img, "user-input")
	if err != nil {
		t.Fatal(err)
	}

	// This accounts for the non-deterministic digest value that we end up with when
	// we build a container image dynamically during testing. Ultimately, we should
	// use a golden image as a test fixture in place of building this image during
	// testing. At that time, this line will no longer be necessary.
	//
	// This value is sourced from the "version" node in "./test-fixtures/snapshot/TestSarifImgsPresenter.golden"
	s.Metadata.ImageMetadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

	pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock())

	return pres
}

func createDirPresenter(t *testing.T) *Presenter {
	matches, packages := createResults()

	s, err := source.NewFromDirectory("/some/path")
	if err != nil {
		t.Fatal(err)
	}

	pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock())

	return pres
}

func Test_imageToSarifReport(t *testing.T) {
	pres := createImagePresenter(t)
	s, err := pres.toSarifReport()
	assert.NoError(t, err)

	assert.Len(t, s.Runs, 1)

	run := s.Runs[0]

	// Sorted by vulnID, pkg name, ...
	assert.Len(t, run.Tool.Driver.Rules, 2)
	assert.Equal(t, run.Tool.Driver.Rules[0].ID, "CVE-1999-0001-package-1")
	assert.Equal(t, run.Tool.Driver.Rules[1].ID, "CVE-1999-0002-package-2")

	assert.Len(t, run.Results, 2)
	result := run.Results[0]
	assert.Equal(t, *result.RuleID, "CVE-1999-0001-package-1")
	assert.Len(t, result.Locations, 1)
	location := result.Locations[0]
	assert.Equal(t, *location.PhysicalLocation.ArtifactLocation.URI, "image/etc/pkg-1")

	result = run.Results[1]
	assert.Equal(t, *result.RuleID, "CVE-1999-0002-package-2")
	assert.Len(t, result.Locations, 1)
	location = result.Locations[0]
	assert.Equal(t, *location.PhysicalLocation.ArtifactLocation.URI, "image/pkg-2")
}

func Test_dirToSarifReport(t *testing.T) {
	pres := createDirPresenter(t)
	s, err := pres.toSarifReport()
	assert.NoError(t, err)

	assert.Len(t, s.Runs, 1)

	run := s.Runs[0]

	// Sorted by vulnID, pkg name, ...
	assert.Len(t, run.Tool.Driver.Rules, 2)
	assert.Equal(t, run.Tool.Driver.Rules[0].ID, "CVE-1999-0001-package-1")
	assert.Equal(t, run.Tool.Driver.Rules[1].ID, "CVE-1999-0002-package-2")

	assert.Len(t, run.Results, 2)
	result := run.Results[0]
	assert.Equal(t, *result.RuleID, "CVE-1999-0001-package-1")
	assert.Len(t, result.Locations, 1)
	location := result.Locations[0]
	assert.Equal(t, *location.PhysicalLocation.ArtifactLocation.URI, "/some/path/etc/pkg-1")

	result = run.Results[1]
	assert.Equal(t, *result.RuleID, "CVE-1999-0002-package-2")
	assert.Len(t, result.Locations, 1)
	location = result.Locations[0]
	assert.Equal(t, *location.PhysicalLocation.ArtifactLocation.URI, "/some/path/pkg-2")
}

func TestSarifPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	pres := createImagePresenter(t)

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

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func TestSarifPresenterDir(t *testing.T) {
	var buffer bytes.Buffer
	pres := createDirPresenter(t)

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

	// remove dynamic values, which are tested independently
	actual = redact(actual)
	expected = redact(expected)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func redact(s []byte) []byte {
	for _, pattern := range []*regexp.Regexp{} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
}
