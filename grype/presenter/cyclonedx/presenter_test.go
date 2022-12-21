package cyclonedx

import (
	"bytes"
	"flag"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for cyclonedx presenters")

// Note: this is a unit test for only encoding the vulnerability matches to a CycloneDX document.
// The full integration test will cover regressions for the entire document. When actual SBOM source are used
func TestCycloneDxPresenter(t *testing.T) {
	tests := []struct {
		name   string
		scheme source.Scheme
		format cyclonedx.BOMFileFormat
	}{
		{
			name:   "image scheme: cyclonedx-json",
			scheme: source.ImageScheme,
			format: cyclonedx.BOMFileFormatJSON,
		},
		{
			name:   "image scheme: cyclonedx-xml",
			scheme: source.ImageScheme,
			format: cyclonedx.BOMFileFormatXML,
		},
		{
			name:   "directory scheme: cyclonedx-json",
			scheme: source.DirectoryScheme,
			format: cyclonedx.BOMFileFormatJSON,
		},
		{
			name:   "directory scheme: cyclonedx-xml",
			scheme: source.DirectoryScheme,
			format: cyclonedx.BOMFileFormatXML,
		},
	}

	for _, test := range tests {
		var buffer bytes.Buffer
		matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, test.scheme)

		pb := models.PresenterBundle{
			Matches:          &matches,
			Packages:         packages,
			Context:          context,
			MetadataProvider: metadataProvider,
			SBOM:             &sbom.SBOM{},
		}

		pres := NewPresenter(pb, test.format)
		// run presenter
		err := pres.Present(&buffer)
		if err != nil {
			t.Fatal(err)
		}

		got := buffer.Bytes()
		testutils.UpdateGoldenFileContents(t, got)

		want := testutils.GetGoldenFileContents(t)
		//// remove dynamic values, which are tested independently
		want = models.Redact(want)
		got = models.Redact(got)

		if !bytes.Equal(want, got) {
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("pres.Present mismatch: %s: (-want +got):\n%s", test.name, diff)
			}
		}
	}
}
