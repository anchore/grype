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
	analysis := models.GenerateAnalysis(t)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	templatePresenter := NewPresenter(templateFilePath)

	var buffer bytes.Buffer
	if err := templatePresenter.Present(&buffer, analysis); err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(actual), string(expected))
}
