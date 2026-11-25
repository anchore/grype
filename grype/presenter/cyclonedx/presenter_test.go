package cyclonedx

import (
	"bytes"
	"flag"
	"os"
	"testing"

	cyclonedxlib "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/testutils"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/sbom"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

func compileCycloneDXSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	c := jsonschema.NewCompiler()

	// the CycloneDX schema references these sub-schemas by URL; pre-load them from vendored files
	// so the compiler doesn't try to fetch from the network
	for _, sub := range []struct {
		url  string
		file string
	}{
		{"http://cyclonedx.org/schema/jsf-0.82.schema.json", "testdata/jsf-0.82.schema.json"},
		{"http://cyclonedx.org/schema/spdx.schema.json", "testdata/spdx.schema.json"},
	} {
		f, err := os.Open(sub.file)
		require.NoError(t, err)
		defer f.Close()

		doc, err := jsonschema.UnmarshalJSON(f)
		require.NoError(t, err)

		require.NoError(t, c.AddResource(sub.url, doc))
	}

	sch, err := c.Compile("testdata/bom-1.6.schema.json")
	require.NoError(t, err)
	return sch
}

func Test_CycloneDX_Valid(t *testing.T) {
	sch := compileCycloneDXSchema(t)

	tests := []struct {
		name   string
		format cyclonedxlib.BOMFileFormat
		scheme internal.SyftSource
	}{
		{
			name:   "json directory",
			format: cyclonedxlib.BOMFileFormatJSON,
			scheme: internal.DirectorySource,
		},
		{
			name:   "json image",
			format: cyclonedxlib.BOMFileFormatJSON,
			scheme: internal.ImageSource,
		},
		{
			name:   "xml directory",
			format: cyclonedxlib.BOMFileFormatXML,
			scheme: internal.DirectorySource,
		},
		{
			name:   "xml image",
			format: cyclonedxlib.BOMFileFormatXML,
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
			case cyclonedxlib.BOMFileFormatJSON:
				pres = NewJSONPresenter(pb)
			case cyclonedxlib.BOMFileFormatXML:
				pres = NewXMLPresenter(pb)
			default:
				t.Fatalf("invalid format: %v", tc.format)
			}

			err := pres.Present(&buffer)
			require.NoError(t, err)

			var jsonBytes []byte
			if tc.format == cyclonedxlib.BOMFileFormatXML {
				// decode XML into a BOM, then re-encode as JSON so we can validate against the JSON schema;
				// bomFormat is a JSON-only field (xml:"-"), so we must set it after decoding
				var bom cyclonedxlib.BOM
				err = cyclonedxlib.NewBOMDecoder(bytes.NewReader(buffer.Bytes()), cyclonedxlib.BOMFileFormatXML).Decode(&bom)
				require.NoError(t, err, "CycloneDX XML output could not be decoded")

				bom.BOMFormat = cyclonedxlib.BOMFormat

				var jsonBuf bytes.Buffer
				err = cyclonedxlib.NewBOMEncoder(&jsonBuf, cyclonedxlib.BOMFileFormatJSON).Encode(&bom)
				require.NoError(t, err, "could not re-encode BOM as JSON")
				jsonBytes = jsonBuf.Bytes()
			} else {
				jsonBytes = buffer.Bytes()
			}

			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
			require.NoError(t, err)

			err = sch.Validate(inst)
			require.NoError(t, err, "CycloneDX %s output does not conform to schema", tc.name)
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

func TestCycloneDXPreservesInputTool(t *testing.T) {
	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)
	pb.SBOM.Descriptor = sbom.Descriptor{Name: "syft", Version: "1.52.0"}

	var input bytes.Buffer
	require.NoError(t, cyclonedxlib.NewBOMEncoder(&input, cyclonedxlib.BOMFileFormatJSON).Encode(cyclonedxhelpers.ToFormatModel(*pb.SBOM)))
	decoded, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(&input)
	require.NoError(t, err)
	pb.SBOM = decoded

	var output bytes.Buffer
	require.NoError(t, NewJSONPresenter(pb).Present(&output))

	var bom cyclonedxlib.BOM
	require.NoError(t, cyclonedxlib.NewBOMDecoder(&output, cyclonedxlib.BOMFileFormatJSON).Decode(&bom))
	require.NotNil(t, bom.Metadata)
	require.NotNil(t, bom.Metadata.Tools)
	require.NotNil(t, bom.Metadata.Tools.Components)
	require.Len(t, *bom.Metadata.Tools.Components, 2)
	require.Equal(t, []string{"syft", pb.ID.Name}, []string{
		(*bom.Metadata.Tools.Components)[0].Name,
		(*bom.Metadata.Tools.Components)[1].Name,
	})
	require.Equal(t, []string{"1.52.0", pb.ID.Version}, []string{
		(*bom.Metadata.Tools.Components)[0].Version,
		(*bom.Metadata.Tools.Components)[1].Version,
	})
}

func TestCycloneDXDoesNotDuplicateInputTool(t *testing.T) {
	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)

	var input bytes.Buffer
	require.NoError(t, NewJSONPresenter(pb).Present(&input))
	decoded, _, _, err := cyclonedxjson.NewFormatDecoder().Decode(&input)
	require.NoError(t, err)
	pb.SBOM = decoded

	var output bytes.Buffer
	require.NoError(t, NewJSONPresenter(pb).Present(&output))

	var bom cyclonedxlib.BOM
	require.NoError(t, cyclonedxlib.NewBOMDecoder(&output, cyclonedxlib.BOMFileFormatJSON).Decode(&bom))
	require.NotNil(t, bom.Metadata)
	require.NotNil(t, bom.Metadata.Tools)
	require.NotNil(t, bom.Metadata.Tools.Components)
	require.Len(t, *bom.Metadata.Tools.Components, 1)
	require.Equal(t, pb.ID.Name, (*bom.Metadata.Tools.Components)[0].Name)
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
