package cli

import (
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
)

type traitAssertion func(tb testing.TB, stdout, stderr string, rc int)

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
