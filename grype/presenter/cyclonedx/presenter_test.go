package cyclonedx

import (
	"bytes"
	"flag"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func TestCycloneDxPresenterImage(t *testing.T) {
	var buffer bytes.Buffer

	sbom, matches, packages, context, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.ImageSource)
	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
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
	actual = internal.Redact(actual)
	expected = internal.Redact(expected)

	require.JSONEq(t, string(expected), string(actual))
}

func TestCycloneDxPresenterDir(t *testing.T) {
	var buffer bytes.Buffer
	sbom, matches, packages, ctx, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.DirectorySource)
	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
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
	actual = internal.Redact(actual)
	expected = internal.Redact(expected)

	require.JSONEq(t, string(expected), string(actual))
}
