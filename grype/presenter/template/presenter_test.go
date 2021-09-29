package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/stretchr/testify/assert"
)

var update = flag.Bool("update", false, "update the *.golden files for template presenters")

func TestPresenter_Present(t *testing.T) {
	matches, packages, context, metadataProvider, appConfig, dbStatus := models.GenerateAnalysis(t)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	templatePresenter := NewPresenter(matches, nil, packages, context, metadataProvider, appConfig, dbStatus, templateFilePath)

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
