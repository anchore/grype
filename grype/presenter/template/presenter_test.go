package template

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"io"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/internal/testutils"
	syftPkg "github.com/anchore/syft/syft/pkg"
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

func TestPresenter_JUnitTemplate_EscapesAttributes(t *testing.T) {
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)

	templateFilePath := path.Join(workingDirectory, "../../../templates/junit.tmpl")

	// every string written into an XML attribute holds characters that must be escaped
	value := `a&<"b`
	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)
	pb.Document.Distro.Name = value
	pb.Document.Distro.Version = value
	for i := range pb.Document.Matches {
		pb.Document.Matches[i].Artifact.Name = value
		pb.Document.Matches[i].Artifact.Version = value
		pb.Document.Matches[i].Artifact.Type = syftPkg.Type(value)
		pb.Document.Matches[i].Vulnerability.ID = value
		pb.Document.Matches[i].Vulnerability.Severity = value
	}

	templatePresenter := NewPresenter(pb, templateFilePath)

	var buffer bytes.Buffer
	require.NoError(t, templatePresenter.Present(&buffer))

	expected := map[string]string{
		"testsuite/name":     value + ":" + value,
		"property/value":     value,
		"testcase/classname": value + "-" + value + " (" + value + ")",
		"testcase/name":      "[" + value + "] " + value,
		"failure/message":    value + ": " + value,
	}
	seen := map[string]int{}
	decoder := xml.NewDecoder(&buffer)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		element, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		for _, attr := range element.Attr {
			key := element.Name.Local + "/" + attr.Name.Local
			if want, ok := expected[key]; ok {
				assert.Equal(t, want, attr.Value, key)
				seen[key]++
			}
		}
	}

	for key := range expected {
		assert.NotZero(t, seen[key], "no %s attribute found", key)
	}
	assert.Equal(t, len(pb.Document.Matches), seen["failure/message"])
}
