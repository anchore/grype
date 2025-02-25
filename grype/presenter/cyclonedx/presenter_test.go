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
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func Test_noTypedNils(t *testing.T) {
	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			FileMetadata: map[file.Coordinates]file.Metadata{},
			FileDigests:  map[file.Coordinates][]file.Digest{},
		},
	}
	c := file.NewCoordinates("/file", "123")
	s.Artifacts.FileMetadata[c] = file.Metadata{
		Path: "/file",
	}
	s.Artifacts.FileDigests[c] = []file.Digest{}

	p := NewJSONPresenter(models.PresenterConfig{
		SBOM:   &s,
		Pretty: false,
	})
	contents := bytes.Buffer{}
	err := p.Present(&contents)
	require.NoError(t, err)
	require.NotContains(t, contents.String(), "null")
}

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
