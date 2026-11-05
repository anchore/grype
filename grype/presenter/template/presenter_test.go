package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
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

func TestPresenter_RejectsTemplateWithoutActions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents string
	}{
		{name: "empty file", contents: ""},
		{name: "literal text", contents: "private value\n"},
		{name: "comment only", contents: "{{/* a comment */}}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			templatePath := path.Join(t.TempDir(), "output.tmpl")
			require.NoError(t, os.WriteFile(templatePath, []byte(tc.contents), 0o600))

			var output bytes.Buffer
			err := NewPresenter(models.PresenterConfig{}, templatePath).Present(&output)
			require.ErrorContains(t, err, "must contain a template action")
			assert.Empty(t, output.String())
		})
	}
}
