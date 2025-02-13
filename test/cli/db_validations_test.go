package cli

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestDBValidations(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			// regression: do not panic on bad DB load
			name: "fail on bad DB load",
			args: []string{"-vv", "dir:."},
			env: map[string]string{
				"GRYPE_DB_CA_CERT": "./does-not-exist.crt",
			},
			assertions: []traitAssertion{
				assertInOutput("failed to load vulnerability db"),
				assertFailingReturnCode,
			},
		},
		{
			// check for a DB update always works when running "grype db check"
			name: "always check for updates",
			args: []string{"-vvv", "db", "check"},
			env: map[string]string{
				"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "10h",
			},
			assertions: []traitAssertion{
				assertInOutput("checking for available database updates"),
				assertFailingReturnCode,
			},
		},
		{
			// check for a DB update always works when running "grype db update"
			name: "always update",
			args: []string{"-vvv", "db", "update"},
			env: map[string]string{
				"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "10h",
			},
			assertions: []traitAssertion{
				assertInOutput("unable to update vulnerability database"),
				assertFailingReturnCode,
			},
		},
		{
			name: "ensure db update frequency config is wired and responsive",
			args: []string{"-vvv", t.TempDir()},
			env: map[string]string{
				"GRYPE_DB_MAX_UPDATE_CHECK_FREQUENCY": "10h",
			},
			assertions: []traitAssertion{
				assertNotInOutput("no max-frequency set for update check"),
				assertInOutput("checking for available database updates"),
				assertInOutput("max-update-check-frequency: 10h"),
				assertFailingReturnCode,
			},
		},
	}

	invalidUpdateURL := fmt.Sprintf("https://localhost:%v", availablePort())
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.env["GRYPE_DB_CACHE_DIR"] = t.TempDir()
			test.env["GRYPE_DB_UPDATE_URL"] = invalidUpdateURL
			cmd, stdout, stderr := runGrype(t, test.env, test.args...)
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
