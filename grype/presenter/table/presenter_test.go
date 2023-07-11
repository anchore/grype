package table

import (
	"bytes"
	"flag"
	"testing"

	"github.com/go-test/deep"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

var update = flag.Bool("update", false, "update the *.golden files for table presenters")

func TestCreateRow(t *testing.T) {
	pkg1 := pkg.Package{
		ID:      "package-1-id",
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
	}
	match1 := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:        "CVE-1999-0001",
			Namespace: "source-1",
		},
		Package: pkg1,
		Details: []match.Detail{
			{
				Type:    match.ExactDirectMatch,
				Matcher: match.DpkgMatcher,
			},
		},
	}
	cases := []struct {
		name           string
		match          match.Match
		severitySuffix string
		expectedErr    error
		expectedRow    []string
	}{
		{
			name:           "create row for vulnerability",
			match:          match1,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "", string(match1.Package.Type), match1.Vulnerability.ID, "Low"},
		},
		{
			name:           "create row for suppressed vulnerability",
			match:          match1,
			severitySuffix: appendSuppressed,
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "", string(match1.Package.Type), match1.Vulnerability.ID, "Low (suppressed)"},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			row, err := createRow(testCase.match, models.NewMetadataMock(), testCase.severitySuffix)

			assert.Equal(t, testCase.expectedErr, err)
			assert.Equal(t, testCase.expectedRow, row)
		})
	}
}

func TestTablePresenter_Color(t *testing.T) {

	var buffer bytes.Buffer
	matches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysis(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, false, false)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestTablePresenter_NoColor(t *testing.T) {

	var buffer bytes.Buffer
	matches, packages, _, metadataProvider, _, _ := models.GenerateAnalysis(t, source.ImageScheme)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, false, true)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyTablePresenter(t *testing.T) {
	// Expected to have no output

	var buffer bytes.Buffer

	matches := match.NewMatches()

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         nil,
		MetadataProvider: nil,
	}

	pres := NewPresenter(pb, false, false)

	// run presenter
	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}

}

func TestRemoveDuplicateRows(t *testing.T) {
	data := [][]string{
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"1", "2", "3"},
		{"4", "5", "6"},
		{"1", "2", "1"},
	}

	expected := [][]string{
		{"1", "2", "3"},
		{"a", "b", "c"},
		{"4", "5", "6"},
		{"1", "2", "1"},
	}

	actual := removeDuplicateRows(data)

	if diffs := deep.Equal(expected, actual); len(diffs) > 0 {
		t.Errorf("found diffs!")
		for _, d := range diffs {
			t.Errorf("   diff: %+v", d)
		}
	}

}

func TestHidesIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer
	matches, ignoredMatches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, false, true)

	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}

func TestDisplaysIgnoredMatches(t *testing.T) {
	var buffer bytes.Buffer
	matches, ignoredMatches, packages, _, metadataProvider, _, _ := internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource)

	pb := models.PresenterConfig{
		Matches:          matches,
		IgnoredMatches:   ignoredMatches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb, true, true)

	err := pres.Present(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if !bytes.Equal(expected, actual) {
		dmp := diffmatchpatch.New()
		diffs := dmp.DiffMain(string(expected), string(actual), true)
		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
	}
}
