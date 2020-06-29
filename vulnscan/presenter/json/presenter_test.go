package json

import (
	"bytes"
	"flag"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/result"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
	"github.com/sergi/go-diff/diffmatchpatch"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")

func TestJsonPresenter(t *testing.T) {

	pres := NewPresenter()
	var buffer bytes.Buffer

	var pkg1 = pkg.Package{
		Name:    "package-1",
		Version: "1.0.1",
		Type:    pkg.DebPkg,
	}

	var pkg2 = pkg.Package{
		Name:    "package-2",
		Version: "2.0.1",
		Type:    pkg.DebPkg,
	}

	var match1 = match.Match{
		Type:          match.ExactDirectMatch,
		Vulnerability: vulnerability.Vulnerability{ID: "CVE-1999-0001"},
		Package:       &pkg1,
	}

	var match2 = match.Match{
		Type:          match.ExactIndirectMatch,
		Vulnerability: vulnerability.Vulnerability{ID: "CVE-1999-0002"},
		Package:       &pkg1,
	}

	results := result.NewResult()

	results.Add(&pkg1, match1, match2)

	catalog := pkg.NewCatalog()

	// populate catalog with test data
	catalog.Add(pkg1)
	catalog.Add(pkg2)

	// TODO: add a constructor for a match.Match when the data is better shaped

	// run presenter
	err := pres.Present(&buffer, catalog, results)
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
	// validateAgainstV1Schema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// Expected to have an empty JSON array back
	pres := NewPresenter()
	var buffer bytes.Buffer

	results := result.NewResult()

	catalog := pkg.NewCatalog()

	// run presenter
	err := pres.Present(&buffer, catalog, results)
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
