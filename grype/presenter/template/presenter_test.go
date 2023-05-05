package template

import (
	"bytes"
	"flag"
	"os"
	"path"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for template presenters")
var timestampRegexp = regexp.MustCompile(`Timestamp:\s*[0-9\-]+`)

func TestPresenter_Present(t *testing.T) {
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

	templatePresenter := NewPresenter(pb, templateFilePath)

	var buffer bytes.Buffer
	if err := templatePresenter.Present(&buffer); err != nil {
		t.Fatal(err)
	}

	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}
	expected := testutils.GetGoldenFileContents(t)

	assert.Equal(t, string(expected), string(actual))
}

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`Timestamp:`))
}
