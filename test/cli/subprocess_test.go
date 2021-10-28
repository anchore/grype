package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func TestSubprocessStdin(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "ensure can be used by node subprocess (without hanging)",
			args: []string{"-v", fmt.Sprintf("%s:%s", repoRoot(t), "/code"), "-w", "/code", imagetest.LoadFixtureImageIntoDocker(t, "image-node-subprocess")},
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

		testWithTimeout(t, test.name, 60*time.Second, testFn)
	}
}
