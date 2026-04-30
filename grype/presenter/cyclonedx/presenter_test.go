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
