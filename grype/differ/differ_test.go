package differ

import (
	"bytes"
	"flag"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/db"
	v4 "github.com/anchore/grype/grype/db/v4"
)

var update = flag.Bool("update", false, "update the *.golden files for diff presenter")

func TestNewDiffer(t *testing.T) {
	//GIVEN
	config := db.Config{}

	//WHEN
	differ, err := NewDiffer(config)

	//THEN
	require.NoError(t, err)
	require.NotNil(t, differ.baseCurator)
}

func TestPresent_Json(t *testing.T) {
	//GIVEN
	diffs := []v4.Diff{
		{v4.DiffAdded, "CVE-1", "nvd", []string{"requests", "vault"}},
		{v4.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
		{v4.DiffChanged, "CVE-3", "nvd", []string{}},
	}
	differ := Differ{}
	var buffer bytes.Buffer

	// WHEN
	require.NoError(t, differ.Present("json", &diffs, &buffer))

	//THEN
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

func TestPresent_Table(t *testing.T) {
	//GIVEN
	diffs := []v4.Diff{
		{v4.DiffAdded, "CVE-1", "nvd", []string{"requests", "vault"}},
		{v4.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
		{v4.DiffChanged, "CVE-3", "nvd", []string{}},
	}
	differ := Differ{}
	var buffer bytes.Buffer

	// WHEN
	require.NoError(t, differ.Present("table", &diffs, &buffer))

	//THEN
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

func TestPresent_Invalid(t *testing.T) {
	//GIVEN
	diffs := []v4.Diff{
		{v4.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
	}
	differ := Differ{}
	var buffer bytes.Buffer

	// WHEN
	err := differ.Present("", &diffs, &buffer)

	//THEN
	require.Error(t, err)
}
