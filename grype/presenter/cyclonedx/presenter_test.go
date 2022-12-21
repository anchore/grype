package cyclonedx

import (
	"bytes"
	"flag"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func TestCycloneDxPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, source.ImageScheme)
	sbom := models.SBOMFromPackages(t, packages)
	pb := models.PresenterBundle{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
		SBOM:             sbom,
	}

	pres := NewPresenter(pb, cyclonedx.BOMFileFormatXML)
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

}

func TestCycloneDxPresenterDir(t *testing.T) {
	var buffer bytes.Buffer
	matches, packages, ctx, metadataProvider, _, _ := models.GenerateAnalysis(t, source.DirectoryScheme)
	pb := models.PresenterBundle{
		Matches:          matches,
		Packages:         packages,
		Context:          ctx,
		MetadataProvider: metadataProvider,
		SBOM:             &sbom.SBOM{},
	}

	pres := NewPresenter(pb, cyclonedx.BOMFileFormatXML)

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

}
