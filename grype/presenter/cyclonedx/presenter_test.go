package cyclonedx

import (
	"bytes"
	"flag"
	"testing"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/testutils"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func Test_CycloneDX_Valid(t *testing.T) {
	tests := []struct {
		name   string
		format cyclonedx.BOMFileFormat
		scheme internal.SyftSource
	}{
		{
			name:   "json directory",
			format: cyclonedx.BOMFileFormatJSON,
			scheme: internal.DirectorySource,
		},
		{
			name:   "json image",
			format: cyclonedx.BOMFileFormatJSON,
			scheme: internal.ImageSource,
		},
		{
			name:   "xml directory",
			format: cyclonedx.BOMFileFormatXML,
			scheme: internal.DirectorySource,
		},
		{
			name:   "xml image",
			format: cyclonedx.BOMFileFormatXML,
			scheme: internal.ImageSource,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buffer bytes.Buffer

			pb := internal.GeneratePresenterConfig(t, tc.scheme)

			var pres *Presenter
			switch tc.format {
			case cyclonedx.BOMFileFormatJSON:
				pres = NewJSONPresenter(pb)
			case cyclonedx.BOMFileFormatXML:
				pres = NewXMLPresenter(pb)
			default:
				t.Fatalf("invalid format: %v", tc.format)
			}

			err := pres.Present(&buffer)
			require.NoError(t, err)

			var bom cyclonedx.BOM
			err = cyclonedx.NewBOMDecoder(&buffer, tc.format).Decode(&bom)
			require.NoError(t, err, "CycloneDX %s output is not valid", tc.name)
		})
	}
}

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

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

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

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}
}

func TestCycloneDxPresenterDir(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)

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

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}
}
