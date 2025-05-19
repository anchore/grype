package differ

import (
	"bytes"
	"flag"
	"strconv"
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/require"

	"github.com/anchore/go-testutils"
	v5 "github.com/anchore/grype/grype/db/v5"
	"github.com/anchore/grype/grype/db/v5/distribution"
)

var update = flag.Bool("update", false, "update the *.golden files for diff presenter")

func TestNewDiffer(t *testing.T) {
	//GIVEN
	config := distribution.Config{}

	//WHEN
	differ, err := NewDiffer(config)

	//THEN
	require.NoError(t, err)
	require.NotNil(t, differ.baseCurator)
}

func Test_DifferDirectory(t *testing.T) {
	d, err := NewDiffer(distribution.Config{
		DBRootDir: "root-dir",
	})
	require.NoError(t, err)

	err = d.SetBaseDB("test-fixtures/dbs/base")
	require.NoError(t, err)

	baseStatus := d.baseCurator.Status()
	require.Equal(t, "test-fixtures/dbs/base/"+strconv.Itoa(v5.SchemaVersion), baseStatus.Location)

	err = d.SetTargetDB("test-fixtures/dbs/target")
	require.NoError(t, err)

	targetStatus := d.targetCurator.Status()
	require.Equal(t, "test-fixtures/dbs/target/"+strconv.Itoa(v5.SchemaVersion), targetStatus.Location)
}

func TestPresent_Json(t *testing.T) {
	//GIVEN
	diffs := []v5.Diff{
		{v5.DiffAdded, "CVE-1", "nvd", []string{"requests", "vault"}},
		{v5.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
		{v5.DiffChanged, "CVE-3", "nvd", []string{}},
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
	diffs := []v5.Diff{
		{v5.DiffAdded, "CVE-1", "nvd", []string{"requests", "vault"}},
		{v5.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
		{v5.DiffChanged, "CVE-3", "nvd", []string{}},
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
	diffs := []v5.Diff{
		{v5.DiffRemoved, "CVE-2", "nvd", []string{"k8s"}},
	}
	differ := Differ{}
	var buffer bytes.Buffer

	// WHEN
	err := differ.Present("", &diffs, &buffer)

	//THEN
	require.Error(t, err)
}
