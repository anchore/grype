package template

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/anchore/grype/grype/presenter/formats/models"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
)

func TestFormat(t *testing.T) {
	analysis := models.GenerateAnalysis(t)

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	templateFilePath := path.Join(workingDirectory, "./test-fixtures/test.template")

	format, err := Format(templateFilePath)
	if err != nil {
		t.Fatal(err)
	}

	var buffer bytes.Buffer
	if err := format(analysis, &buffer); err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(actual), string(expected))
}
