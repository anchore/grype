package cyclonedxvex

import (
	"bytes"
	"flag"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", true, "update the *.golden files for json presenters")

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

			matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t)

			pres := NewPresenter(matches, packages, context.Source, metadataProvider, true, tcase.format)
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
			actual = models.Redact(actual)
			expected = models.Redact(expected)

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
			matches, packages, _, metadataProvider, _, _ := models.GenerateAnalysis(t)

			s, err := source.NewFromDirectory("/some/path")
			if err != nil {
				t.Fatal(err)
			}
			pres := NewPresenter(matches, packages, &s.Metadata, metadataProvider, true, tcase.format)

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
			actual = models.Redact(actual)
			expected = models.Redact(expected)

			if !bytes.Equal(expected, actual) {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(string(expected), string(actual), true)
				t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
