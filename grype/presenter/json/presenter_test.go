package json

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

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
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)
	var expectedJSON, actualJSON models.Document

	if err := json.Unmarshal(expected, &expectedJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", expected, err.Error()))
	}

	if err := json.Unmarshal(actual, &actualJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Input ('%s') is not valid json.\nJSON parsing error: '%s'", actual, err.Error()))
	}

	assert.NotEmpty(t, actualJSON.Descriptor.Timestamp)
	// Check format is RFC3339 compatible e.g. 2023-04-21T00:22:06.491137+01:00
	_, err := time.Parse(time.RFC3339, actualJSON.Descriptor.Timestamp)
	if assert.NoError(t, err) {
		actualJSON.Descriptor.Timestamp = expectedJSON.Descriptor.Timestamp
		assert.Equal(t, expectedJSON, actualJSON)
	}

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

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)
	var expectedJSON, actualJSON models.Document

	if err := json.Unmarshal(expected, &expectedJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", expected, err.Error()))
	}

	if err := json.Unmarshal(actual, &actualJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Input ('%s') is not valid json.\nJSON parsing error: '%s'", actual, err.Error()))
	}

	assert.NotEmpty(t, actualJSON.Descriptor.Timestamp)
	// Check format is RFC3339 compatible e.g. 2023-04-21T00:22:06.491137+01:00
	_, err := time.Parse(time.RFC3339, actualJSON.Descriptor.Timestamp)
	if assert.NoError(t, err) {
		actualJSON.Descriptor.Timestamp = expectedJSON.Descriptor.Timestamp
		assert.Equal(t, expectedJSON, actualJSON)
	}

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
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)
	var expectedJSON, actualJSON models.Document

	if err := json.Unmarshal(expected, &expectedJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Expected value ('%s') is not valid json.\nJSON parsing error: '%s'", expected, err.Error()))
	}

	if err := json.Unmarshal(actual, &actualJSON); err != nil {
		assert.Fail(t, fmt.Sprintf("Input ('%s') is not valid json.\nJSON parsing error: '%s'", actual, err.Error()))
	}

	assert.NotEmpty(t, actualJSON.Descriptor.Timestamp)
	// Check format is RFC3339 compatible e.g. 2023-04-21T00:22:06.491137+01:00
	_, err := time.Parse(time.RFC3339, actualJSON.Descriptor.Timestamp)
	if assert.NoError(t, err) {
		actualJSON.Descriptor.Timestamp = expectedJSON.Descriptor.Timestamp
		assert.Equal(t, expectedJSON, actualJSON)
	}

}
