package cli

import (
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		assertions []traitAssertion
	}{
		{
			name: "finds vulnerabilities in a ubuntu image",
			args: []string{"registry:ghcr.io/anchore/test-images/vex-oci-attach@sha256:8b95adbdf01ad43043ea9b63d6ac56abbe0e81b67fe40a27c39b6b83488f70ce"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				// in vex doc
				assertInOutput("CVE-2016-20013"),
				assertInOutput("CVE-2022-3219"),
				// not in vex doc
				assertInOutput("CVE-2020-22916"),
				assertInOutput("CVE-2024-2236"),
			},
		},
		{
			name: "filters out vulnerabilities based on local vex document",
			args: []string{"registry:ghcr.io/anchore/test-images/vex-oci-attach@sha256:8b95adbdf01ad43043ea9b63d6ac56abbe0e81b67fe40a27c39b6b83488f70ce", "--vex", "test-fixtures/vex/test-images-vex-oci-attach.vex.json"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				// in vex doc
				assertNotInOutput("CVE-2016-20013"),
				assertNotInOutput("CVE-2022-3219"),
				// not in vex doc
				assertInOutput("CVE-2020-22916"),
				assertInOutput("CVE-2024-2236"),
			},
		},
		{
			name: "filters out vulnerabilities based on vex autodiscovery",
			args: []string{"registry:ghcr.io/anchore/test-images/vex-oci-attach@sha256:8b95adbdf01ad43043ea9b63d6ac56abbe0e81b67fe40a27c39b6b83488f70ce", "--vex-autodiscover"},
			assertions: []traitAssertion{
				assertSucceedingReturnCode,
				// in vex doc
				assertNotInOutput("CVE-2016-20013"),
				assertNotInOutput("CVE-2022-3219"),
				// not in vex doc
				assertInOutput("CVE-2020-22916"),
				assertInOutput("CVE-2024-2236"),
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
