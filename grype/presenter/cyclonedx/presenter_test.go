package cyclonedx

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func TestCycloneDxPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, source.ImageScheme)
	sbom := models.SBOMFromPackages(t, packages)
	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
		SBOM:             sbom,
	}

	pres := NewJSONPresenter(pb)
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

	require.JSONEq(t, string(expected), string(actual))
}

func TestCycloneDxPresenterDir(t *testing.T) {
	var buffer bytes.Buffer
	matches, packages, ctx, metadataProvider, _, _ := models.GenerateAnalysis(t, source.DirectoryScheme)
	sbom := models.SBOMFromPackages(t, packages)
	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          ctx,
		MetadataProvider: metadataProvider,
		SBOM:             sbom,
	}

	pres := NewJSONPresenter(pb)

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

	require.JSONEq(t, string(expected), string(actual))
}
