package cli

import (
	"strings"
	"testing"
)

func TestCmd(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "no-args-shows-help",
			args: []string{},
			assertions: []traitAssertion{
				assertInOutput("an image/directory argument is required"),                              // specific error that should be shown
				assertInOutput("A vulnerability scanner for container images, filesystems, and SBOMs"), // excerpt from help description
				assertFailingReturnCode,
			},
		},
		{
			name: "ensure valid descriptor",
			args: []string{getFixtureImage(t, "image-bare"), "-o", "json"},
			assertions: []traitAssertion{
				assertInOutput(`"check-for-app-update": false`), // assert existence of the app config block
				assertInOutput(`"db": {`),                       // assert existence of the db status block
				assertInOutput(`"built":`),                      // assert existence of the db status block
			},
		},
		{
			name: "platform-option-wired-up",
			args: []string{"--platform", "arm64", "-o", "json", "registry:busybox:1.31"},
			assertions: []traitAssertion{
				assertInOutput("sha256:1ee006886991ad4689838d3a288e0dd3fd29b70e276622f16b67a8922831a853"), // linux/arm64 image digest
			},
		},
		{
			name: "responds-to-search-options",
			args: []string{"-vv"},
			env: map[string]string{
				"GRYPE_SEARCH_UNINDEXED_ARCHIVES": "true",
				"GRYPE_SEARCH_INDEXED_ARCHIVES":   "false",
				"GRYPE_SEARCH_SCOPE":              "all-layers",
			},
			assertions: []traitAssertion{
				// the application config in the log matches that of what we expect to have been configured. Note:
				// we are not testing further wiring of this option, only that the config responds to
				// package-cataloger-level options.
				assertInOutput("unindexed-archives: true"),
				assertInOutput("indexed-archives: false"),
				assertInOutput("scope: all-layers"),
			},
		},
		{
			name: "vulnerabilities in output on -f with failure",
			args: strings.Split("alpine:3.12.11 -f critical --only-fixed --platform linux/amd64", " "),
			assertions: []traitAssertion{
				assertInOutput("CVE-2022-37434"), // a known vulnerability in the alpine:3.12.11 image
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd, stdout, stderr := runGrype(t, test.env, test.args...)
			for _, traitFn := range test.assertions {
				traitFn(t, stdout, stderr, cmd.ProcessState.ExitCode())
			}
			if t.Failed() {
				t.Log("STDOUT:\n", stdout)
				t.Log("STDERR:\n", stderr)
				t.Log("COMMAND:", strings.Join(cmd.Args, " "))
			}
		})
	}
}
