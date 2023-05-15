package json

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")
var timestampRegexp = regexp.MustCompile(`"timestamp":\s*"[^"]+"`)

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, source.ImageScheme)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	matches, packages, context, metadataProvider, _, _ := models.GenerateAnalysis(t, source.DirectoryScheme)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		Context:          context,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// Expected to have an empty JSON array back
	var buffer bytes.Buffer

	matches := match.NewMatches()

	ctx := pkg.Context{
		Source: &source.Metadata{},
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         nil,
		Context:          ctx,
		MetadataProvider: nil,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

}

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`"timestamp":""`))
}
