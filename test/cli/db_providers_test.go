package cli

import (
	"strings"
	"testing"
)

func TestDBProviders(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "db providers command",
			args: []string{"db", "providers"},
			assertions: []traitAssertion{
				assertInOutput("LAST SUCCESSFUL RUN"),
				assertNoStderr,
				assertTableReport,
			},
		},
		{
			name: "db providers command help",
			args: []string{"db", "providers", "-h"},
			assertions: []traitAssertion{
				assertInOutput("List vulnerability providers that are in the database"),
				assertNoStderr,
			},
		},
		{
			name: "db providers command with table output flag",
			args: []string{"db", "providers", "-o", "table"},
			assertions: []traitAssertion{
				assertInOutput("LAST SUCCESSFUL RUN"),
				assertNoStderr,
				assertTableReport,
			},
		},
		{
			name: "db providers command with json output flag",
			args: []string{"db", "providers", "-o", "json"},
			assertions: []traitAssertion{
				assertInOutput("providers"),
				assertNoStderr,
				assertJsonReport,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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
