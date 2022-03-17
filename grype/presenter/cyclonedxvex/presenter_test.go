package cyclonedxvex

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/imagetest"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func createResults() (match.Matches, []pkg.Package) {

	pkg1 := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
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

func TestCycloneDxPresenterImage(t *testing.T) {
	for _, tcase := range []struct {
		name   string
		format cyclonedx.BOMFileFormat
	}{
		{name: "json", format: cyclonedx.BOMFileFormatJSON},
		{name: "xml", format: cyclonedx.BOMFileFormatXML},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			var buffer bytes.Buffer

			matches, packages := createResults()

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-simple")
			s, _ := source.NewFromImage(img, "user-input")

			// This accounts for the non-deterministic digest value that we end up with when
			// we build a container image dynamically during testing. Ultimately, we should
			// use a golden image as a test fixture in place of building this image during
			// testing. At that time, this line will no longer be necessary.
			//
			// This value is sourced from the "version" node in "./test-fixtures/snapshot/TestCycloneDxImgsPresenter.golden"
			s.Metadata.ImageMetadata.ManifestDigest = "sha256:2731251dc34951c0e50fcc643b4c5f74922dad1a5d98f302b504cf46cd5d9368"

			pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock(), true, tcase.format)
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
		})
	}
}

func TestCycloneDxPresenterDir(t *testing.T) {
	for _, tcase := range []struct {
		name   string
		format cyclonedx.BOMFileFormat
	}{
		{name: "json", format: cyclonedx.BOMFileFormatJSON},
		{name: "xml", format: cyclonedx.BOMFileFormatXML},
	} {
		t.Run(tcase.name, func(t *testing.T) {
			var buffer bytes.Buffer
			matches, packages := createResults()

			s, err := source.NewFromDirectory("/some/path")
			if err != nil {
				t.Fatal(err)
			}
			pres := NewPresenter(matches, packages, &s.Metadata, models.NewMetadataMock(), true, tcase.format)

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
				diffs := dmp.DiffMain(string(expected), string(actual), true)
				t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}

func redact(s []byte) []byte {
	serialPattern := regexp.MustCompile(`urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	rfc3339Pattern := regexp.MustCompile(`([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))`)

	for _, pattern := range []*regexp.Regexp{serialPattern, rfc3339Pattern} {
		s = pattern.ReplaceAll(s, []byte("redacted"))
	}
	return s
}
