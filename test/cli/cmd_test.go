package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
			name: "empty-string-arg-shows-help",
			args: []string{""},
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
				assertInOutput(`"check-for-app-update":`), // assert existence of the app config block
				assertInOutput(`"db":`),                   // assert existence of the db status block
				assertInOutput(`"built":`),                // assert existence of the db status block
			},
		},
		{
			name: "platform-option-wired-up",
			args: []string{"--platform", "arm64", "-o", "json", "registry:busybox:1.31"},
			assertions: []traitAssertion{
				assertInOutput("sha256:1ee006886991ad4689838d3a288e0dd3fd29b70e276622f16b67a8922831a853"), // linux/arm64 image digest
			},
		},
		// TODO: uncomment this test when we can use `grype config`
		//{
		//	name: "responds-to-search-options",
		//	args: []string{"--help"},
		//	env: map[string]string{
		//		"GRYPE_SEARCH_UNINDEXED_ARCHIVES": "true",
		//		"GRYPE_SEARCH_INDEXED_ARCHIVES":   "false",
		//		"GRYPE_SEARCH_SCOPE":              "all-layers",
		//	},
		//	assertions: []traitAssertion{
		//		// the application config in the log matches that of what we expect to have been configured. Note:
		//		// we are not testing further wiring of this option, only that the config responds to
		//		// package-cataloger-level options.
		//		assertInOutput("unindexed-archives: true"),
		//		assertInOutput("indexed-archives: false"),
		//		assertInOutput("scope: 'all-layers'"),
		//	},
		//},
		{
			name: "vulnerabilities in output on -f with failure",
			args: []string{"registry:busybox:1.31", "-f", "high", "--platform", "linux/amd64"},
			assertions: []traitAssertion{
				assertInOutput("CVE-2021-42379"),
				assertFailingReturnCode,
			},
		},
		{
			name: "reason for ignored vulnerabilities is available in the template",
			args: []string{
				"sbom:" + filepath.Join("test-fixtures", "test-ignore-reason", "sbom.json"),
				"-c", filepath.Join("test-fixtures", "test-ignore-reason", "config-with-ignore.yaml"),
				"-o", "template",
				"-t", filepath.Join("test-fixtures", "test-ignore-reason", "template-with-ignore-reasons"),
			},
			assertions: []traitAssertion{
				assertInOutput("CVE-2021-42385 (test reason for vulnerability being ignored)"),
				assertSucceedingReturnCode,
			},
		},
		{
			name: "ignore-states wired up",
			args: []string{"./test-fixtures/sbom-grype-source.json", "--ignore-states", "unknown"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				assertRowInStdOut([]string{"Pygments", "2.6.1", "2.7.4", "python", "GHSA-pq64-v7f5-gqh8", "High"}),
				assertNotInOutput("CVE-2014-6052"),
			},
		},
		{
			name: "ignore-states wired up - ignore fixed",
			args: []string{"./test-fixtures/sbom-grype-source.json", "--ignore-states", "fixed"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				assertRowInStdOut([]string{"libvncserver", "0.9.9", "apk", "CVE-2014-6052", "High"}),
				assertNotInOutput("GHSA-pq64-v7f5-gqh8"),
			},
		},
		{
			name: "ignore-states wired up - ignore fixed, show suppressed",
			args: []string{"./test-fixtures/sbom-grype-source.json", "--ignore-states", "fixed", "--show-suppressed"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				assertRowInStdOut([]string{"Pygments", "2.6.1", "2.7.4", "python", "GHSA-pq64-v7f5-gqh8", "High", "(suppressed)"}),
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

func Test_descriptorNameAndVersionSet(t *testing.T) {
	_, output, _ := runGrype(t, nil, "-o", "json", getFixtureImage(t, "image-bare"))

	parsed := map[string]any{}
	err := json.Unmarshal([]byte(output), &parsed)
	require.NoError(t, err)

	desc, _ := parsed["descriptor"].(map[string]any)
	require.NotNil(t, desc)

	name := desc["name"]
	require.Equal(t, "grype", name)

	version := desc["version"]
	require.NotEmpty(t, version)
}
