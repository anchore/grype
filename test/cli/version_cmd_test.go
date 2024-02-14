package cli

import (
	"testing"
)

func TestVersionCmdPrintsToStdout(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "version command prints to stdout",
			assertions: []traitAssertion{
				assertInOutput("Version:"),
				assertNoStderr,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgCmd, pkgsStdout, pkgsStderr := runGrype(t, test.env, "version")
			for _, traitFn := range test.assertions {
				traitFn(t, pkgsStdout, pkgsStderr, pkgCmd.ProcessState.ExitCode())
			}
		})
	}
}
