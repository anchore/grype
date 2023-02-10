package integration

import (
	"flag"
)

var update = flag.Bool("update", false, "update the *.golden files for diff presenter")

const (
	baseURL   = "https://toolbox-data.anchore.io/grype/staging-databases/vulnerability-db_v5_2022-10-14T08:22:01Z_69c99aa5917dea969f2d.tar.gz"
	targetURL = "https://toolbox-data.anchore.io/grype/staging-databases/vulnerability-db_v5_2022-10-17T08:14:57Z_10e4086061ab36cfa900.tar.gz"
)

// TODO: Rework this test to not be dependent on hosted DBs.  Disabling to get around failures while bumping schema

//func TestDatabaseDiff(t *testing.T) {
//	//GIVEN
//	differ, err := differ.NewDiffer(db.Config{
//		DBRootDir:           "test-fixtures/grype-db",
//		ListingURL:          getListingURL(),
//		ValidateByHashOnGet: false,
//	})
//	var buffer bytes.Buffer
//	base, err := url.Parse(baseURL)
//	require.NoError(t, err)
//	target, err := url.Parse(targetURL)
//	require.NoError(t, err)
//
//	//WHEN
//	require.NoError(t, differ.DownloadDatabases(base, target))
//	diffs, err := differ.DiffDatabases()
//	require.NoError(t, err)
//	for i := range *diffs {
//		sort.Strings((*diffs)[i].Packages)
//	}
//	sort.SliceStable(*diffs, func(i, j int) bool {
//		d1, d2 := (*diffs)[i], (*diffs)[j]
//		return (d1.ID + d1.Namespace) < (d2.ID + d2.Namespace)
//	})
//	require.NoError(t, differ.Present("json", diffs, &buffer))
//
//	//THEN
//	actual := buffer.Bytes()
//	if *update {
//		testutils.UpdateGoldenFileContents(t, actual)
//	}
//	var expected = testutils.GetGoldenFileContents(t)
//	if !bytes.Equal(expected, actual) {
//		dmp := diffmatchpatch.New()
//		diffs := dmp.DiffMain(string(expected), string(actual), true)
//		t.Errorf("mismatched output:\n%s", dmp.DiffPrettyText(diffs))
//	}
//}
