package json

import (
	"bytes"
	"flag"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/clio"
	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")
var timestampRegexp = regexp.MustCompile(`"timestamp":\s*"[^"]+"`)

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer
	_, matches, packages, context, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.ImageSource)

	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
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

	_, matches, packages, context, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.DirectorySource)

	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
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
		Source: &source.Description{},
		Distro: &linux.Release{
			ID:      "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
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

func TestPresenter_Present_NewDocumentSorted(t *testing.T) {
	_, matches, packages, context, metadataProvider, appConfig, dbStatus := internal.GenerateAnalysis(t, internal.ImageSource)
	doc, err := models.NewDocument(clio.Identification{}, packages, context, matches, nil, metadataProvider, appConfig, dbStatus)
	if err != nil {
		t.Fatal(err)
	}

	if !sort.IsSorted(models.MatchSort(doc.Matches)) {
		t.Errorf("expected matches to be sorted")
	}
}

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`"timestamp":""`))
}
