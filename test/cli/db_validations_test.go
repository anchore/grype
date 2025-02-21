package cli

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	dbtest "github.com/anchore/grype/grype/db/v6/testutil"
)

func TestDBValidations(t *testing.T) {
	invalidUpdateURL := fmt.Sprintf("https://localhost:%v", availablePort())
	expiredDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(-24*24*time.Hour)).SetDBVersion(6, 0, 0).Start() // 24 days old
	yesterdayDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(-24*time.Hour)).SetDBVersion(6, 0, 0).Start()  // 24 hours old
	todayDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now()).SetDBVersion(6, 0, 0).Start()                         // just built
	notFoundDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(3 * time.Hour)).WithHandler(http.NotFound).Start()

	// common setup functions
	type setupFunc = func(t *testing.T, dir string)
	setup := func(funcs ...setupFunc) setupFunc {
		return func(t *testing.T, dir string) {
			for _, f := range funcs {
				f(t, dir)
			}
		}
	}

	setupDb := func(url string) setupFunc {
		return func(t *testing.T, dir string) {
			cmd, stdout, stderr := runGrype(t, map[string]string{
				"GRYPE_DB_CACHE_DIR":  dir,
				"GRYPE_DB_UPDATE_URL": url,
			}, "db", "update", "-vvv")
			assertInOutput("downloading new vulnerability DB")(t, stdout, stderr, cmd.ProcessState.ExitCode())
			assertSucceedingReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
		}
	}
	setupExpiredDb := setupDb(expiredDbURL)
	setupYesterdayDb := setupDb(yesterdayDbURL)
	setupTodayDb := setupDb(todayDbURL)

	dbFilePath := func(dir string) string {
		return filepath.Join(dir, "6", "vulnerability.db")
	}

	corruptDb := func(t *testing.T, dir string) {
		err := os.Truncate(dbFilePath(dir), 20)
		require.NoError(t, err)
	}

	moveDbToBackup := func(t *testing.T, dir string) {
		err := os.Rename(dbFilePath(dir), filepath.Join(dir, "db.old"))
		require.NoError(t, err)
	}

	restoreDbFromBackup := func(t *testing.T, dir string) {
		// replace with valid db, which doesn't match the hash
		err := os.Rename(filepath.Join(dir, "db.old"), dbFilePath(dir))
		require.NoError(t, err)
	}

	deleteDb := func(t *testing.T, dir string) {
		err := os.Remove(dbFilePath(dir))
		require.NoError(t, err)
	}

	// common asserts
	assertDbDownloaded := assertInOutput("downloading new vulnerability DB")
	assertDbNotDownloaded := assertNotInOutput("downloading new vulnerability DB")
	assertScanRan := assertInOutput("No vulnerabilities found")
	assertDbLoadFailed := assertInOutput("failed to load vulnerability db")
	assertDbLoadNotAtempted := assertNotInOutput("failed to load vulnerability db")
	assertDbNotFound := assertInOutput("No installed DB version found")
	assertCheckedForDbUpdate := assertInOutput("checking for available database updates")
	assertDbHashed := assertInOutput("captured DB digest")
	assertUpdateMessageDisplayed := assertInOutput("update to the latest db")
	cmdAliases := map[string]string{"scan": "pkg:no/thing@0"} // scan: matching a purl with no vulnerabilities

	// ensure we have grype built and ready
	runGrype(t, map[string]string{}, "config")

	tests := []struct {
		name                      string    // the portion of the name before `:` is the command to run from cmdAliases above or the literal value
		setup                     setupFunc // setup to run before test cmd
		dbUpdateURL               string    // update url to use, e.g. todayDbURL
		dbRequireUpdate           bool      // whether an update check is required
		dbMaxUpdateCheckFrequency string    // max update check frequency, defaults to 0 to always check
		dbValidateHash            bool      // whether to validate existing db by hash
		dbValidateAge             bool      // whether to validate existing db age
		dbCaCert                  string    // ca cert file, if set
		assertions                []traitAssertion
	}{
		{
			name:        "scan: new install downloads successfully",
			setup:       nil,
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "scan: existing db updates successfully",
			setup:       setupYesterdayDb,
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertDbHashed,
				assertDbDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "scan: existing db skips update when same",
			setup:       setupYesterdayDb,
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbNotDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "scan: existing db skips update when newer",
			setup:       setupTodayDb,
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbNotDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "scan: continues on corrupt db no update",
			setup:       setup(setupYesterdayDb, corruptDb),
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "db check: continues on corrupt db no update",
			setup:       setup(setupYesterdayDb, corruptDb),
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbNotFound,
				assertFailingReturnCode,
			},
		},
		{
			name:        "db check: continues on corrupt db with update",
			setup:       setup(setupYesterdayDb, corruptDb),
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertDbNotFound,
				assertFailingReturnCode,
			},
		},
		{
			name:        "db status: fails with corrupt db no update",
			setup:       setup(setupYesterdayDb, corruptDb),
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbNotDownloaded,
				assertInOutput("failed to read DB metadata"),
				assertFailingReturnCode,
			},
		},
		{
			name:        "db status: fails with corrupt db with update",
			setup:       setup(setupYesterdayDb, corruptDb),
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertDbNotDownloaded,
				assertInOutput("failed to read DB metadata"),
				assertFailingReturnCode,
			},
		},
		{
			name:        "scan: missing db downloads a new one",
			setup:       setup(setupYesterdayDb, deleteDb),
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertDbDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:        "db check: missing db does not affect no update",
			setup:       setup(setupYesterdayDb, deleteDb),
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertDbNotFound,
				assertFailingReturnCode,
			},
		},
		{
			name:        "db check: missing db does not affect with update",
			setup:       setup(setupYesterdayDb, deleteDb),
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertDbNotFound,
				assertFailingReturnCode,
			},
		},
		{
			name:        "db status: missing db returns error",
			setup:       setup(setupYesterdayDb, deleteDb),
			dbUpdateURL: todayDbURL,
			assertions: []traitAssertion{
				assertInOutput("database does not exist"),
				assertFailingReturnCode,
			},
		},
		{
			name:           "db status: valid db fails with hash mismatch",
			setup:          setup(setupYesterdayDb, moveDbToBackup, setupTodayDb, deleteDb, restoreDbFromBackup),
			dbUpdateURL:    invalidUpdateURL,
			dbValidateHash: true,
			assertions: []traitAssertion{
				assertInOutput("bad db checksum"),
				assertFailingReturnCode,
			},
		},
		{
			name:           "db check: valid db with hash mismatch",
			setup:          setup(setupYesterdayDb, moveDbToBackup, setupTodayDb, deleteDb, restoreDbFromBackup),
			dbUpdateURL:    invalidUpdateURL,
			dbValidateHash: true,
			assertions: []traitAssertion{
				assertDbLoadNotAtempted,
				assertFailingReturnCode,
			},
		},
		{
			name:           "scan: valid db fails with hash mismatch",
			setup:          setup(setupYesterdayDb, moveDbToBackup, setupTodayDb, deleteDb, restoreDbFromBackup),
			dbUpdateURL:    invalidUpdateURL,
			dbValidateHash: true,
			assertions: []traitAssertion{
				assertInOutput("bad db checksum"),
				assertDbLoadFailed,
				assertDbNotDownloaded,
				// notification mentions grype db delete and grype db update
				assertInOutput("grype db delete"),
				assertInOutput("grype db update"),
				assertFailingReturnCode,
			},
		},
		{
			name: "scan: missing import.json",
			setup: setup(setupYesterdayDb, func(t *testing.T, dir string) {
				require.NoError(t, os.Remove(filepath.Join(filepath.Dir(dbFilePath(dir)), "import.json")))
			}),
			dbUpdateURL:    invalidUpdateURL,
			dbValidateHash: true,
			assertions: []traitAssertion{
				assertInOutput("no import metadata"),
				assertDbLoadFailed,
				assertDbNotDownloaded,
				// notification mentions grype db delete and grype db update
				assertInOutput("grype db delete"),
				assertInOutput("grype db update"),
				assertFailingReturnCode,
			},
		},
		{
			name:            "scan: update check error with valid db continues",
			setup:           setupYesterdayDb,
			dbUpdateURL:     notFoundDbURL,
			dbRequireUpdate: false,
			assertions: []traitAssertion{
				assertInOutput("error updating db"),
				assertSucceedingReturnCode,
			},
		},
		{
			name:            "scan: update check error with valid db fails when require update",
			setup:           setupYesterdayDb,
			dbUpdateURL:     notFoundDbURL,
			dbRequireUpdate: true,
			assertions: []traitAssertion{
				assertInOutput("unable to update db"),
				assertFailingReturnCode,
			},
		},
		{
			name:            "db check: update check error with valid db fails",
			setup:           setupYesterdayDb,
			dbUpdateURL:     notFoundDbURL,
			dbRequireUpdate: false,
			assertions: []traitAssertion{
				assertInOutput("unable to check for vulnerability database update"),
				assertFailingReturnCode,
			},
		},
		{
			name:          "scan: database older than max age fails when unable to update",
			setup:         setupExpiredDb,
			dbUpdateURL:   notFoundDbURL,
			dbValidateAge: true,
			assertions: []traitAssertion{
				assertInOutput("the vulnerability database was built"),
				assertFailingReturnCode,
			},
		},
		{
			name:          "scan: database older than max age succeeds with update",
			setup:         setupExpiredDb,
			dbUpdateURL:   todayDbURL,
			dbValidateAge: true,
			assertions: []traitAssertion{
				assertDbDownloaded,
				assertScanRan,
				assertSucceedingReturnCode,
			},
		},
		{
			name:     "scan: no panic on bad cert configuration",
			dbCaCert: "./does-not-exist.crt",
			assertions: []traitAssertion{
				assertInOutput("failed to load vulnerability db"),
				assertFailingReturnCode,
			},
		},
		{
			name:                      "db check: always check for updates regardless of frequency",
			setup:                     setupYesterdayDb,
			dbUpdateURL:               todayDbURL,
			dbMaxUpdateCheckFrequency: "10h",
			assertions: []traitAssertion{
				assertCheckedForDbUpdate,
				assertUpdateMessageDisplayed,
				func(tb testing.TB, stdout, stderr string, rc int) {
					require.Equal(t, 100, rc)
				},
			},
		},
		{
			name:                      "db update: always update regardless of frequency",
			setup:                     setupYesterdayDb,
			dbUpdateURL:               todayDbURL,
			dbMaxUpdateCheckFrequency: "10h",
			assertions: []traitAssertion{
				assertCheckedForDbUpdate,
				assertDbDownloaded,
				assertSucceedingReturnCode,
			},
		},
		{
			name:                      "scan: ensure db update frequency config is respected",
			setup:                     setupYesterdayDb,
			dbUpdateURL:               todayDbURL,
			dbMaxUpdateCheckFrequency: "10h", // last check was during setup, much more recently than 10h ago
			assertions: []traitAssertion{
				assertNotInOutput("no max-frequency set for update check"),
				assertNotInOutput("checking for available database updates"),
				assertDbNotDownloaded,
				assertInOutput("max-update-check-frequency: 10h"),
				assertSucceedingReturnCode,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			dbDir := t.TempDir()
			if test.setup != nil {
				test.setup(t, dbDir)
			}

			// set up values
			env := map[string]string{
				"GRYPE_DB_CACHE_DIR":                  dbDir,
				"GRYPE_DB_UPDATE_URL":                 defaultValue(test.dbUpdateURL, invalidUpdateURL),
				"GRYPE_DB_VALIDATE_BY_HASH_ON_START":  fmt.Sprintf("%v", defaultValue(test.dbValidateHash, false)),
				"GRYPE_DB_VALIDATE_AGE":               fmt.Sprintf("%v", defaultValue(test.dbValidateAge, false)),
				"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": defaultValue(test.dbMaxUpdateCheckFrequency, "0"),
			}
			if test.dbValidateAge {
				env["GRYPE_DB_MAX_ALLOWED_BUILT_AGE"] = "48h" // expired db is 24 days old
			}
			if test.dbCaCert != "" {
				env["GRYPE_DB_CA_CERT"] = test.dbCaCert
			}
			if test.dbRequireUpdate {
				env["GRYPE_DB_REQUIRE_UPDATE_CHECK"] = "true"
			}

			// test name before : is command args
			args := strings.Split(test.name, ":")
			args = strings.Split(args[0], " ")
			if cmd := cmdAliases[args[0]]; cmd != "" {
				args[0] = cmd
			}
			cmd, stdout, stderr := runGrype(t, env, append(args, "-vvv")...)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}

func defaultValue[T comparable](value T, defaultValue T) T {
	var empty T
	if value == empty {
		return defaultValue
	}
	return value
}

func availablePort() int {
	if a, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer func() { _ = l.Close() }()
			return l.Addr().(*net.TCPAddr).Port
		}
	}
	panic("unable to get port")
}
