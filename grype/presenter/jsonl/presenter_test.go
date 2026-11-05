package jsonl

import (
	"bytes"
	"encoding/json"
	"flag"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/testutils"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for jsonl presenter")

func TestJSONLImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)
	pres := NewPresenter(pb)

	require.NoError(t, pres.Present(&buffer))
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}
	expected := testutils.GetGoldenFileContents(t)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}

	// every emitted line must independently parse as JSON
	for i, line := range nonEmptyLines(actual) {
		var v map[string]any
		require.NoErrorf(t, json.Unmarshal(line, &v), "line %d is not valid JSON: %q", i, string(line))
	}
}

func TestJSONLDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)
	pres := NewPresenter(pb)

	require.NoError(t, pres.Present(&buffer))
	actual := buffer.Bytes()

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}
	expected := testutils.GetGoldenFileContents(t)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}
}

func TestEmptyJSONLPresenter(t *testing.T) {
	// no matches → no output (empty stream is a valid jsonl document).
	var buffer bytes.Buffer

	ctx := pkg.Context{
		Source: &source.Description{},
		Distro: &distro.Distro{
			Type:    "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	doc, err := models.NewDocument(clio.Identification{Name: "grype", Version: "[not provided]"}, nil, ctx, match.NewMatches(), nil, models.NewMetadataMock(), nil, nil, models.SortByPackage, true, nil)
	require.NoError(t, err)

	pb := models.PresenterConfig{
		ID:       clio.Identification{Name: "grype", Version: "[not provided]"},
		Document: doc,
	}

	pres := NewPresenter(pb)
	require.NoError(t, pres.Present(&buffer))

	assert.Equal(t, 0, buffer.Len(), "empty match set should produce no output")
}

func TestJSONLLineCountMatchesDocument(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)
	pres := NewPresenter(pb)
	require.NoError(t, pres.Present(&buffer))

	got := len(nonEmptyLines(buffer.Bytes()))
	want := len(pb.Document.Matches)
	assert.Equal(t, want, got, "expected one jsonl line per match in the document")
}

func nonEmptyLines(b []byte) [][]byte {
	var out [][]byte
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(strings.TrimSpace(string(line))) > 0 {
			out = append(out, line)
		}
	}
	return out
}
