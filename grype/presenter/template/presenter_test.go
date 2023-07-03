package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
)

var update = flag.Bool("update", false, "update the *.golden files for template presenters")

func TestPresenter_Present(t *testing.T) {
	matches, packages, context, metadataProvider, appConfig, dbStatus := internal.GenerateAnalysis(t, internal.ImageSource)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
		AppConfig:        appConfig,
		DBStatus:         dbStatus,
	}

	templatePresenter := NewPresenter(afero.NewMemMapFs(), pb, "", templateFilePath)

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

func TestPresenter_PresentWithOutputFile(t *testing.T) {
	matches, packages, context, metadataProvider, appConfig, dbStatus := models.GenerateAnalysis(t, source.ImageScheme)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
		AppConfig:        appConfig,
		DBStatus:         dbStatus,
	}

	outputFilePath := "/tmp/report.test.txt"
	fs := afero.NewMemMapFs()
	templatePresenter := NewPresenter(fs, pb, outputFilePath, templateFilePath)

	var buffer bytes.Buffer
	if err := templatePresenter.Present(&buffer); err != nil {
		t.Fatal(err)
	}

	f, err := fs.Open(outputFilePath)
	if err != nil {
		t.Fatalf("no output file: %+v", err)
	}

	outputContent, err := afero.ReadAll(f)
	if err != nil {
		t.Fatalf("could not read file: %+v", err)
	}

	if *update {
		testutils.UpdateGoldenFileContents(t, outputContent)
	}
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(expected), string(outputContent))
}

func TestPresenter_SprigDate_Fails(t *testing.T) {
	matches, packages, context, metadataProvider, appConfig, dbStatus := internal.GenerateAnalysis(t, internal.ImageSource)
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	// this template has the generic sprig date function, which is intentionally not supported for security reasons
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template.sprig.date")

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
		AppConfig:        appConfig,
		DBStatus:         dbStatus,
	}

	templatePresenter := NewPresenter(afero.NewMemMapFs(), pb, "", templateFilePath)

	var buffer bytes.Buffer
	err = templatePresenter.Present(&buffer)
	require.ErrorContains(t, err, `function "now" not defined`)
}
