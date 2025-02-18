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
	yesterdayDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(-1 * 24 * time.Hour)).Start()
	updatedDbURL := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(1 * time.Hour)).Start()
	handlerServer := dbtest.NewServer(t).SetDBBuilt(time.Now().Add(3 * time.Hour))
	handlerServerURL := handlerServer.Start()

	setupYesterdayDatabase := func(dir string) {
		cmd, stdout, stderr := runGrype(t, map[string]string{
			"GRYPE_DB_CACHE_DIR":  dir,
			"GRYPE_DB_UPDATE_URL": yesterdayDbURL,
		}, "db", "update", "-vvv")
		assertInOutput("downloading new vulnerability DB")(t, stdout, stderr, cmd.ProcessState.ExitCode())
		assertSucceedingReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
	}

	tests := []struct {
		name                      string
		setup                     func(dir string)
		dbRequireUpdate           bool
		dbUpdateURL               string
		dbMaxUpdateCheckFrequency string
		dbCaCert                  string
		args                      []string
		assertions                []traitAssertion
	}{
		{
			name:        "new install downloads successfully",
			args:        []string{"dir:."},
			dbUpdateURL: yesterdayDbURL,
			assertions: []traitAssertion{
				assertInOutput("downloaded new vulnerability DB"),
				assertInOutput("No vulnerabilities found"),
				assertSucceedingReturnCode,
			},
		},
		{
			name:                      "existing database updates successfully",
			args:                      []string{"dir:."},
			setup:                     setupYesterdayDatabase,
			dbUpdateURL:               updatedDbURL,
			dbMaxUpdateCheckFrequency: "1ms",
			assertions: []traitAssertion{
				assertInOutput("captured DB checksum"),
				assertInOutput("downloading new vulnerability DB"),
				assertInOutput("No vulnerabilities found"),
				assertSucceedingReturnCode,
			},
		},
		{
			name:                      "existing database skips update when not new",
			args:                      []string{"dir:."},
			setup:                     setupYesterdayDatabase,
			dbUpdateURL:               yesterdayDbURL,
			dbMaxUpdateCheckFrequency: "1ms",
			assertions: []traitAssertion{
				assertNotInOutput("downloading new vulnerability DB"),
				assertInOutput("No vulnerabilities found"),
				assertSucceedingReturnCode,
			},
		},
		{
			name: "corrupt database returns error",
			args: []string{"dir:."},
			setup: func(dir string) {
				setupYesterdayDatabase(dir)
				err := os.Truncate(filepath.Join(dir, "6", "vulnerability.db"), 20)
				require.NoError(t, err)
			},
			dbUpdateURL: updatedDbURL,
			assertions: []traitAssertion{
				assertInOutput("failed to load vulnerability db"),
				assertFailingReturnCode,
			},
		},
		{
			name:                      "continues on update check error with valid database",
			args:                      []string{"dir:."},
			dbMaxUpdateCheckFrequency: "1ms",
			dbRequireUpdate:           false,
			setup: func(dir string) {
				setupYesterdayDatabase(dir)
				handlerServer.RequestHandler = func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				}
			},
			dbUpdateURL: handlerServerURL,
			assertions: []traitAssertion{
				assertInOutput("error updating db"),
				assertSucceedingReturnCode,
			},
		},
		{
			name:                      "fails when update check fails and require update is set",
			args:                      []string{"dir:."},
			dbMaxUpdateCheckFrequency: "1ms",
			dbRequireUpdate:           true,
			setup: func(dir string) {
				setupYesterdayDatabase(dir)
				handlerServer.RequestHandler = func(w http.ResponseWriter, r *http.Request) {
					http.NotFound(w, r)
				}
			},
			dbUpdateURL: handlerServerURL,
			assertions: []traitAssertion{
				assertInOutput("unable to update db"),
				assertFailingReturnCode,
			},
		},
		{
			name:     "no panic on bad cert configuration",
			args:     []string{"dir:."},
			dbCaCert: "./does-not-exist.crt",
			assertions: []traitAssertion{
				assertInOutput("failed to load vulnerability db"),
				assertFailingReturnCode,
			},
		},
		{
			// check for a DB update always works when running "grype db check"
			name:                      "always check for updates",
			args:                      []string{"db", "check"},
			dbMaxUpdateCheckFrequency: "10h",
			assertions: []traitAssertion{
				assertInOutput("checking for available database updates"),
				assertFailingReturnCode,
			},
		},
		{
			// check for a DB update always works when running "grype db update"
			name:                      "always update",
			args:                      []string{"db", "update"},
			dbMaxUpdateCheckFrequency: "10h",
			assertions: []traitAssertion{
				assertInOutput("unable to update vulnerability database"),
				assertFailingReturnCode,
			},
		},
		{
			name:                      "ensure db update frequency config is wired and responsive",
			args:                      []string{t.TempDir()},
			dbMaxUpdateCheckFrequency: "10h",
			assertions: []traitAssertion{
				assertNotInOutput("no max-frequency set for update check"),
				assertInOutput("checking for available database updates"),
				assertInOutput("max-update-check-frequency: 10h"),
				assertFailingReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dbDir := t.TempDir()
			if test.setup != nil {
				test.setup(dbDir)
			}

			// set up values
			env := map[string]string{
				"GRYPE_DB_CACHE_DIR":  dbDir,
				"GRYPE_DB_UPDATE_URL": defaultValue(test.dbUpdateURL, invalidUpdateURL),
			}
			if test.dbMaxUpdateCheckFrequency != "" {
				env["GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY"] = test.dbMaxUpdateCheckFrequency
			}
			if test.dbCaCert != "" {
				env["GRYPE_DB_CA_CERT"] = test.dbCaCert
			}
			if test.dbRequireUpdate {
				env["GRYPE_DB_REQUIRE_UPDATE_CHECK"] = "true"
			}

			cmd, stdout, stderr := runGrype(t, env, append(test.args, "-vvv")...)
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
