package integration

import (
	"bytes"
	"flag"
	"net/url"
	"sort"
	"testing"

	"github.com/anchore/go-testutils"
	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/differ"
	"github.com/sergi/go-diff/diffmatchpatch"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "update the *.golden files for diff presenter")

const (
	baseURL   = "https://toolbox-data.anchore.io/grype/databases/vulnerability-db_v4_2022-07-05T08:18:22Z_39868af44fc51829a7c9.tar.gz"
	targetURL = "https://toolbox-data.anchore.io/grype/databases/vulnerability-db_v4_2022-07-06T08:16:42Z_c840f17244dea46d0c07.tar.gz"
)

func TestDatabaseDiff(t *testing.T) {
	//GIVEN
	differ, err := differ.NewDiffer(db.Config{
		DBRootDir:           "test-fixtures/grype-db",
		ListingURL:          getListingURL(),
		ValidateByHashOnGet: false,
	})
	var buffer bytes.Buffer
	base, err := url.Parse(baseURL)
	require.NoError(t, err)
	target, err := url.Parse(targetURL)
	require.NoError(t, err)

	//WHEN
	require.NoError(t, differ.DownloadDatabases(base, target))
	diffs, err := differ.DiffDatabases()
	require.NoError(t, err)
	for i, _ := range *diffs {
		sort.Strings((*diffs)[i].Packages)
	}
	sort.SliceStable(*diffs, func(i, j int) bool {
		d1, d2 := (*diffs)[i], (*diffs)[j]
		return (d1.ID + d1.Namespace) < (d2.ID + d2.Namespace)
	})
	require.NoError(t, differ.Present("json", diffs, &buffer))

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
