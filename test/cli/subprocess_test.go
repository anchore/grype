package cli

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

// TestSubprocessStdin ensures grype does not hang when it is invoked as a subprocess with an open
// (but empty) stdin pipe: "stdin is a pipe" must not be the only indicator used to decide that
// analysis input is coming from stdin.
//
// Everything the container needs is mounted in -- the grype binary, a locally built vulnerability
// DB, and an SBOM to scan -- so nothing in the timed section of this test reaches out to the
// network. Downloading the real DB and pulling an image from a registry inside the container is
// what made this test exceed its timeout in CI.
func TestSubprocessStdin(t *testing.T) {
	const timeout = 60 * time.Second

	binDir := path.Dir(getGrypeSnapshotLocation(t, "linux", "amd64"))
	dbDir := seedTestDB(t)
	sbom := filepath.Join(repoRoot(t), "test", "cli", "testdata", "sbom-ubuntu-20.04--pruned.json")

	commonArgs := []string{
		"--rm",
		"-v", fmt.Sprintf("%s:%s:ro", binDir, "/app/bin"),
		"-v", fmt.Sprintf("%s:%s:ro", sbom, "/sbom.json"),
		"-v", fmt.Sprintf("%s:%s", dbDir, "/db"),
		// note: these must be passed with -e to reach grype inside the container
		"-e", "GRYPE_CHECK_FOR_APP_UPDATE=false",
		"-e", "GRYPE_DB_CACHE_DIR=/db",
		"-e", "GRYPE_DB_AUTO_UPDATE=false",
	}

	// note: each call gets its own copy so appends never share a backing array
	dockerArgs := func(args ...string) []string {
		return append(append([]string{}, commonArgs...), args...)
	}

	tests := []struct {
		name       string
		args       []string
		assertions []traitAssertion
	}{
		{
			// regression
			name: "ensure can be used by node subprocess (without hanging)",
			args: dockerArgs(imagetest.LoadFixtureImageIntoDocker(t, "image-node-subprocess"), "node", "/app.js"),
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
			},
		},
		{
			// regression: https://github.com/anchore/grype/issues/267
			name: "ensure can be used by java subprocess (without hanging)",
			args: dockerArgs(imagetest.LoadFixtureImageIntoDocker(t, "image-java-subprocess"), "java", "/app.java"),
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			cmd := getDockerRunCommandContext(ctx, t, test.args...)
			stdout, stderr := runCommand(cmd, nil)

			if ctx.Err() != nil {
				t.Errorf("grype did not exit within %s (it is likely hanging on stdin)", timeout)
			}

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
