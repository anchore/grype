package cli

import (
	"strings"
	"testing"
)

func TestJsonDescriptor(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "ensure valid descriptor",
			args: []string{getFixtureImage(t, "image-bare"), "-o", "json"},
			env: map[string]string{
				"GRYPE_CHECK_FOR_APP_UPDATE": "false",
			},
			assertions: []traitAssertion{
				assertInOutput(`"check-for-app-update": false`), // assert existence of the app config block
				assertInOutput(`"db": {`),                       // assert existence of the db status block
				assertInOutput(`"built":`),                      // assert existence of the db status block
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runGrypeCommand(t, test.env, test.args...)
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
