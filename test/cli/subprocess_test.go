package cli

import (
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func TestSubprocessStdin(t *testing.T) {
	binDir := path.Dir(getGrypeSnapshotLocation(t, "linux"))
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			// regression
			name: "ensure can be used by node subprocess (without hanging)",
			args: []string{"-v", fmt.Sprintf("%s:%s:ro", binDir, "/app/bin"), imagetest.LoadFixtureImageIntoDocker(t, "image-node-subprocess"), "node", "/app.js"},
			env: map[string]string{
				"GRYPE_CHECK_FOR_APP_UPDATE": "false",
			},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
			},
		},
		{
			// regression: https://github.com/anchore/grype/issues/267
			name: "ensure can be used by java subprocess (without hanging)",
			args: []string{"-v", fmt.Sprintf("%s:%s:ro", binDir, "/app/bin"), imagetest.LoadFixtureImageIntoDocker(t, "image-java-subprocess"), "java", "/app.java"},
			env: map[string]string{
				"GRYPE_CHECK_FOR_APP_UPDATE": "false",
			},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
			},
		},
	}

	for _, test := range tests {
		testFn := func(t *testing.T) {
			cmd := getDockerRunCommand(t, test.args...)
			stdout, stderr := runCommand(cmd, test.env)
			for _, traitAssertionFn := range test.assertions {
				traitAssertionFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		}

		// each case runs grype in a container with an empty DB cache, so the
		// budget has to cover downloading and importing the vulnerability DB
		// (~140MB compressed, ~1.5GB on disk) plus pulling the scanned image,
		// on top of the hang this case is actually guarding against. Keep the
		// per-case budget well under the suite-wide -timeout so a real hang
		// still fails here, with a useful message, rather than panicking the
		// whole package.
		testWithTimeout(t, test.name, 3*time.Minute, testFn)
	}
}
