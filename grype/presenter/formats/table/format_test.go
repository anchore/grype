package table

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/grype/grype/presenter/formats/models"

	"github.com/anchore/grype/grype"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestTablePresenter(t *testing.T) {

	var buffer bytes.Buffer

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    syftPkg.DebPkg,
	}

	var match1 = match.Match{
		Type: match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:           "CVE-1999-0001",
			RecordSource: "source-1",
		},
		Package: pkg1,
		Matcher: match.DpkgMatcher,
	}

	var match2 = match.Match{
		Type: match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{
			ID:             "CVE-1999-0002",
			RecordSource:   "source-2",
			FixedInVersion: "the-next-version",
		},
		Package: pkg2,
		Matcher: match.DpkgMatcher,
		SearchKey: map[string]interface{}{
			"some": "key",
		},
	}

	matches := match.NewMatches()

	matches.Add(pkg1, match1, match2)

	packages := []pkg.Package{pkg1, pkg2}

	analysis := grype.Analysis{
		Matches:          matches,
		Packages:         packages,
		MetadataProvider: models.NewMetadataMock(),
	}

	// TODO: add a constructor for a match.Match when the data is better shaped

	err := Format(analysis, &buffer)
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

	analysis := grype.Analysis{
		Matches:          matches,
		Packages:         []pkg.Package{},
		MetadataProvider: models.NewMetadataMock(),
	}

	err := Format(analysis, &buffer)
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
