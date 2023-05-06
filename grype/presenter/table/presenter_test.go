package table

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for table presenters")

func TestCreateRow(t *testing.T) {

	matches, _, _, _, _, _ := models.GenerateAnalysis(t, source.ImageScheme)
	var match1, match2, match3 match.Match

	for m := range matches.Enumerate() {
		switch m.Vulnerability.ID {
		case "CVE-1999-0001":
			match1 = m
		case "CVE-1999-0002":
			match2 = m
		case "CVE-1999-0003":
			match3 = m
		}
	}

	match4 := match.Match{
		Vulnerability: match2.Vulnerability,
		Details:       match2.Details,
		Package: pkg.Package{
			ID:      match2.Package.ID,
			Name:    match2.Package.Name,
			Version: match2.Package.Version,
			Type:    syftPkg.ApkPkg,
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
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "the-next-version", string(match1.Package.Type), match1.Vulnerability.ID, "Low", ""},
		},
		{
			name:           "create row for suppressed vulnerability",
			match:          match1,
			severitySuffix: appendSuppressed,
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "the-next-version", string(match1.Package.Type), match1.Vulnerability.ID, "Low (suppressed)", ""},
		},
		{
			name:           "create row for suppressed location (rpm)",
			match:          match1,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match1.Package.Name, match1.Package.Version, "the-next-version", string(match1.Package.Type), match1.Vulnerability.ID, "Low", ""},
		},
		{
			name:           "create row for suppressed location (deb)",
			match:          match2,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match2.Package.Name, match2.Package.Version, "", string(match2.Package.Type), match2.Vulnerability.ID, "Critical", ""},
		},
		{
			name:           "create row for location",
			match:          match3,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match3.Package.Name, match3.Package.Version, "", string(match3.Package.Type), match3.Vulnerability.ID, "High", strings.Join(match3.Package.Locations.CoordinateSet().Paths(), ", ")},
		},
		{
			name:           "create row for suppressed location (apk)",
			match:          match4,
			severitySuffix: "",
			expectedErr:    nil,
			expectedRow:    []string{match4.Package.Name, match4.Package.Version, "", string(match4.Package.Type), match4.Vulnerability.ID, "Critical", ""},
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

func TestTablePresenter(t *testing.T) {

	var buffer bytes.Buffer
	matches, packages, _, metadataProvider, _, _ := models.GenerateAnalysis(t, source.ImageScheme)

	pb := models.PresenterConfig{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: metadataProvider,
	}

	pres := NewPresenter(pb)

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

	pres := NewPresenter(pb)

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
