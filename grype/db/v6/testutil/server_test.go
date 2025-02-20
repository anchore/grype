package dbtest_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	dbtest "github.com/anchore/grype/grype/db/v6/testutil"
	"github.com/anchore/grype/grype/search"
)

func Test_NewServer(t *testing.T) {
	dbDir := t.TempDir()

	day := 24 * time.Hour

	srv := dbtest.NewServer(t)
	srv.DBBuildTime = time.Now().Add(-1 * day) // one day ago
	url := srv.Start()

	distConfig := distribution.Config{
		ID: clio.Identification{
			Name:           "test",
			Version:        "1",
			GitCommit:      "abcd",
			GitDescription: "main",
			BuildDate:      "now",
		},
		LatestURL:          url,
		CACert:             "",
		RequireUpdateCheck: false,
		CheckTimeout:       0,
		UpdateTimeout:      0,
	}

	installConfig := installation.Config{
		DBRootDir:               dbDir,
		Debug:                   false,
		ValidateAge:             false,
		ValidateChecksum:        false,
		MaxAllowedBuiltAge:      1 * time.Second,
		UpdateCheckMaxFrequency: 0, // don't apply update check interval
	}

	distClient, err := distribution.NewClient(distConfig)
	require.NoError(t, err)

	curator, err := installation.NewCurator(installConfig, distClient)
	require.NoError(t, err)

	// test on a new installation with available db
	didUpdate, err := curator.Update()
	require.NoError(t, err)
	require.True(t, didUpdate) // no database, should update

	// test on an existing installation with NO update
	didUpdate, err = curator.Update()
	require.NoError(t, err)
	require.False(t, didUpdate) // existing database, should not update

	rdr, err := v6.NewReader(v6.Config{
		DBDirPath: filepath.Join(dbDir, "6"),
		Debug:     false,
	})
	require.NoError(t, err)

	vp := v6.NewVulnerabilityProvider(rdr)
	vulns, err := vp.FindVulnerabilities(search.ByID("CVE-2024-1234"))
	require.NoError(t, err)
	require.NotEmpty(t, vulns)

	err = vp.Close()
	require.NoError(t, err)

	// test on an existing installation with an update
	srv.SetDBBuilt(time.Now().Add(1 * day)) // newer than 1 day ago

	didUpdate, err = curator.Update()
	require.NoError(t, err)
	require.True(t, didUpdate) // has update, should update
}
