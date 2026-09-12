package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/testutils"
)

var update = flag.Bool("update", false, "update the *.golden files for template presenters")

func TestPresenter_Present(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./testdata/test.template")

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	templatePresenter := NewPresenter(pb, templateFilePath)

	var buffer bytes.Buffer
	if err := templatePresenter.Present(&buffer); err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(expected), string(actual))
}

func TestPresenter_HTMLTemplate_VulnerabilityDBCollapsible(t *testing.T) {
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	// render the built-in HTML template against a document that carries DB metadata
	templateFilePath := path.Join(workingDirectory, "../../../templates/html.tmpl")

	s, _ := internal.GenerateAnalysis(t, internal.ImageSource)

	dbInfo := struct {
		Status    *vulnerability.ProviderStatus
		Providers map[string]vulnerability.DataProvenance
	}{
		Status: &vulnerability.ProviderStatus{
			SchemaVersion: "1.0",
			Built:         time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		Providers: map[string]vulnerability.DataProvenance{},
	}

	ctx := pkg.Context{Source: &s.Source}
	packages := pkg.FromPtrs(pkg.FromCollection(s.Artifacts.Packages, s.Relationships, pkg.SynthesisConfig{}))

	doc, err := models.NewDocument(
		clio.Identification{Name: "grype", Version: "devel"},
		packages,
		ctx,
		match.NewMatches(),
		nil, // ignoredMatches
		nil, // metadataProvider
		nil, // appConfig
		dbInfo,
		models.SortByPackage,
		false, // outputTimestamp
		nil,   // distroAlerts
	)
	require.NoError(t, err)

	htmlPresenter := NewPresenter(models.PresenterConfig{Document: doc}, templateFilePath)

	var buffer bytes.Buffer
	require.NoError(t, htmlPresenter.Present(&buffer))

	html := buffer.String()

	// the vulnerability DB details must be collapsible so they do not dominate the report
	assert.Contains(t, html, "<summary>Show details</summary>")
	assert.Contains(t, html, "<pre>")
	assert.Contains(t, html, `"schemaVersion":"1.0"`)
}

func TestPresenter_SprigDate_Fails(t *testing.T) {
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	// this template has the generic sprig date function, which is intentionally not supported for security reasons
	templateFilePath := path.Join(workingDirectory, "./testdata/test.template.sprig.date")

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	templatePresenter := NewPresenter(pb, templateFilePath)

	var buffer bytes.Buffer
	err = templatePresenter.Present(&buffer)
	require.ErrorContains(t, err, `function "now" not defined`)
}
