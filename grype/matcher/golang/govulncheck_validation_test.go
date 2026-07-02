package golang

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGoSymbols_GovulncheckAgreement cross-validates the gosymbols matcher
// expectations against govulncheck (golang.org/x/vuln), the reference
// implementation for symbol-level Go vulnerability analysis. For each compiled
// fixture it asserts that govulncheck's symbol-reachability verdict for the
// advisory under test agrees with what the matcher tests expect: the advisory
// is "called" exactly when our tests expect a match.
//
// Only the fixtures that pin a vulnerable *module* version are comparable: the
// stdlib fixtures aren't, because the toolchain-baked stdlib version is current
// (the matcher tests override it to go1.18.0, which govulncheck cannot
// emulate). Assertions are scoped to the specific advisory IDs so that new
// advisories published against the pinned old module versions (e.g. x/net/html
// parsing issues) don't break the test.
//
// Known intentional differences from govulncheck (not covered here, pinned in
// TestGoVulnDB_CustomRangesOnRealRecords instead): for records where the
// standard OSV range is a bare introduced:0 with the real windows only in
// ecosystem_specific.custom_ranges (e.g. GO-2025-4004), govulncheck bails and
// assumes vulnerable; grype emits the real windows.
//
// govulncheck consults the live vuln.go.dev database and so needs network
// access; the test skips unless govulncheck is installed (or GOVULNCHECK
// points at a binary):
//
//	go install golang.org/x/vuln/cmd/govulncheck@latest
func TestGoSymbols_GovulncheckAgreement(t *testing.T) {
	govulncheck := os.Getenv("GOVULNCHECK")
	if govulncheck == "" {
		var err error
		govulncheck, err = exec.LookPath("govulncheck")
		if err != nil {
			t.Skip("govulncheck not installed; `go install golang.org/x/vuln/cmd/govulncheck@latest` or set GOVULNCHECK to run this validation")
		}
	}

	tests := []struct {
		fixture    string
		advisory   string
		wantCalled bool
	}{
		{"gobin-xnet-http2server", "GO-2022-0969", true},
		{"gobin-xnet-html", "GO-2022-0969", false},
		{"gobin-gjson-get", "GO-2021-0265", true},
		{"gobin-gjson-valid", "GO-2021-0265", false},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			called := govulncheckCalledAdvisories(t, govulncheck, tt.fixture)
			if got := called[tt.advisory]; got != tt.wantCalled {
				t.Errorf("govulncheck disagrees on %s for %s: called=%v, matcher tests expect %v (all called: %v)",
					tt.advisory, tt.fixture, got, tt.wantCalled, called)
			}
		})
	}

	// Intentional divergences: cases where grype and govulncheck must NOT agree,
	// because grype's build-time merge uses the aliased GHSA's version ranges
	// where govulndb's are open-ended (packages that predate or don't follow Go
	// module versioning — GHSA usually has the better ranges there).
	//
	// GO-2022-0635/GO-2022-0646 (aws-sdk-go S3 crypto client): govulndb has
	// introduced:0 with no fix, so govulncheck reports every aws-sdk-go version
	// as affected — including the current one the fixture pins ("Fixed in: N/A").
	// The GHSA bounds the range at < 1.34.0 (fixed 2020), so grype's merged
	// record correctly does not match the fixture (asserted in
	// TestMatcherGolang_GoSymbols_GHSAMerge). This subtest pins govulncheck's
	// side of the divergence so we notice if the upstream data ever changes.
	t.Run("gobin-awss3crypto is flagged by govulncheck but out of grype's merged GHSA range", func(t *testing.T) {
		called := govulncheckCalledAdvisories(t, govulncheck, "gobin-awss3crypto")
		if !called["GO-2022-0635"] {
			t.Errorf("expected govulncheck to report GO-2022-0635 on a current aws-sdk-go (open-ended govulndb range); "+
				"if this changed, the upstream record may now be bounded and the intentional-divergence docs should be revisited (all called: %v)", called)
		}
	})
}

// govulncheckCalledAdvisories builds the fixture binary and returns the set of
// advisory IDs govulncheck considers reachable ("called"): findings whose call
// trace names a function, as opposed to module/package-level findings emitted
// for every advisory in range.
func govulncheckCalledAdvisories(t *testing.T, govulncheck, fixture string) map[string]bool {
	t.Helper()
	fixtureDir := filepath.Join("testdata", fixture)

	build := exec.Command("make")
	build.Dir = fixtureDir
	out, err := build.CombinedOutput()
	require.NoErrorf(t, err, "building fixture %q:\n%s", fixture, string(out))

	cmd := exec.Command(govulncheck, "-mode=binary", "-json", "./binary")
	cmd.Dir = fixtureDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// with -json govulncheck exits 0 even when vulnerabilities are found; any
	// error here is an environment problem (e.g. no network to vuln.go.dev)
	require.NoErrorf(t, cmd.Run(), "running govulncheck on %q:\n%s", fixture, stderr.String())

	type message struct {
		Finding *struct {
			OSV   string `json:"osv"`
			Trace []struct {
				Function string `json:"function"`
			} `json:"trace"`
		} `json:"finding"`
	}

	called := map[string]bool{}
	dec := json.NewDecoder(&stdout)
	for {
		var m message
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decoding govulncheck output for %q: %v", fixture, err)
		}
		if m.Finding == nil || len(m.Finding.Trace) == 0 {
			continue
		}
		if m.Finding.Trace[0].Function != "" {
			called[m.Finding.OSV] = true
		}
	}
	return called
}
