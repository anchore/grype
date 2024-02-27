package cli

import (
	"strings"
	"testing"
)

func TestRegistryAuth(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "fallback to keychain",
			args: []string{"-vv", "registry:localhost:5000/something:latest"},
			assertions: []traitAssertion{
				assertInOutput("from registry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`no registry credentials configured for "localhost:5000", using the default keychain`),
			},
		},
		{
			name: "use creds",
			args: []string{"-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"GRYPE_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
				"GRYPE_REGISTRY_AUTH_USERNAME":  "username",
				"GRYPE_REGISTRY_AUTH_PASSWORD":  "password",
			},
			assertions: []traitAssertion{
				assertInOutput("from registry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`using basic auth for registry "localhost:5000"`),
			},
		},
		{
			name: "use token",
			args: []string{"-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"GRYPE_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
				"GRYPE_REGISTRY_AUTH_TOKEN":     "my-token",
			},
			assertions: []traitAssertion{
				assertInOutput("from registry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`using token for registry "localhost:5000"`),
			},
		},
		{
			name: "not enough info fallsback to keychain",
			args: []string{"-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"GRYPE_REGISTRY_AUTH_AUTHORITY": "localhost:5000",
			},
			assertions: []traitAssertion{
				assertInOutput("from registry"),
				assertInOutput("localhost:5000/something:latest"),
				assertInOutput(`no registry credentials configured for "localhost:5000", using the default keychain`),
			},
		},
		{
			name: "allows insecure http flag",
			args: []string{"-vv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"GRYPE_REGISTRY_INSECURE_USE_HTTP": "true",
			},
			assertions: []traitAssertion{
				assertInOutput("insecure-use-http: true"),
			},
		},
		{
			name: "use tls configuration",
			args: []string{"-vvv", "registry:localhost:5000/something:latest"},
			env: map[string]string{
				"GRYPE_REGISTRY_AUTH_TLS_CERT": "place.crt",
				"GRYPE_REGISTRY_AUTH_TLS_KEY":  "place.key",
			},
			assertions: []traitAssertion{
				assertInOutput("using custom TLS credentials from"),
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
