package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
)

type traitAssertion func(tb testing.TB, stdout, stderr string, rc int)

func assertNoStderr(tb testing.TB, _, stderr string, _ int) {
	tb.Helper()
	if len(stderr) > 0 {
		tb.Errorf("expected stderr to be empty, but wasn't")
	}
}

func assertInOutput(data string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()

		if !strings.Contains(stripansi.Strip(stderr), data) && !strings.Contains(stripansi.Strip(stdout), data) {
			tb.Errorf("data=%q was NOT found in any output, but should have been there", data)
		}
	}
}

func assertFailingReturnCode(tb testing.TB, _, _ string, rc int) {
	tb.Helper()
	if rc == 0 {
		tb.Errorf("expected a failure but got rc=%d", rc)
	}
}

func assertSucceedingReturnCode(tb testing.TB, _, _ string, rc int) {
	tb.Helper()
	if rc != 0 {
		tb.Errorf("expected to succeed but got rc=%d", rc)
	}
}

func assertRowInStdOut(row []string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		tb.Helper()

		for _, line := range strings.Split(stdout, "\n") {
			lineMatched := false
			for _, column := range row {
				if !strings.Contains(line, column) {
					// it wasn't this line
					lineMatched = false
					break
				}
				lineMatched = true
			}
			if lineMatched {
				return
			}
		}
		// none of the lines matched
		tb.Errorf("expected stdout to contain %s, but it did not", strings.Join(row, " "))
	}
}

func assertNotInOutput(notWanted string) traitAssertion {
	return func(tb testing.TB, stdout, stderr string, _ int) {
		if strings.Contains(stdout, notWanted) {
			tb.Errorf("got unwanted %s in stdout %s", notWanted, stdout)
		}
	}
}

func assertJsonReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	var data interface{}

	if err := json.Unmarshal([]byte(stdout), &data); err != nil {
		tb.Errorf("expected to find a JSON report, but was unmarshalable: %+v", err)
	}
}

func assertTableReport(tb testing.TB, stdout, _ string, _ int) {
	tb.Helper()
	if !strings.Contains(stdout, "NAME") || !strings.Contains(stdout, "LAST SUCCESSFUL RUN") {
		tb.Errorf("expected to find a table report, but did not")
	}
}
