package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
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

	templatePresenter := NewPresenter(pb, templateFilePath, false)

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

func TestPresenter_Present_LegacyModel(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// this template uses the legacy Go struct document model
	templateFilePath := path.Join(workingDirectory, "./testdata/test.legacy.template")

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	templatePresenter := NewPresenter(pb, templateFilePath, true)

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

func TestShippedTemplates_Render(t *testing.T) {
	// all templates shipped in the repository must render against the JSON data model
	templateFiles, err := filepath.Glob(filepath.Join("..", "..", "..", "templates", "*.tmpl"))
	require.NoError(t, err)
	require.NotEmpty(t, templateFiles)

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	for _, templateFilePath := range templateFiles {
		t.Run(filepath.Base(templateFilePath), func(t *testing.T) {
			templatePresenter := NewPresenter(pb, templateFilePath, false)

			var buffer bytes.Buffer
			require.NoError(t, templatePresenter.Present(&buffer))
			require.NotEmpty(t, buffer.String())
		})
	}
}

func TestPresenter_SprigDate_Fails(t *testing.T) {
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	// this template has the generic sprig date function, which is intentionally not supported for security reasons
	templateFilePath := path.Join(workingDirectory, "./testdata/test.template.sprig.date")

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	templatePresenter := NewPresenter(pb, templateFilePath, false)

	var buffer bytes.Buffer
	err = templatePresenter.Present(&buffer)
	require.ErrorContains(t, err, `function "now" not defined`)
}
