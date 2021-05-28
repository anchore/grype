package template

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/presenter/models"

	"github.com/anchore/go-testutils"
)

func TestPresenter_Present(t *testing.T) {
	matches, packages, context, metadataProvider, appConfig, dbStatus := models.GenerateAnalysis(t)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	templatePresenter := NewPresenter(matches, packages, context, metadataProvider, appConfig, dbStatus, templateFilePath)

	var buffer bytes.Buffer
	if err := templatePresenter.Present(&buffer); err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(expected), string(actual))
}
