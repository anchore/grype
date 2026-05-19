package osv

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/provider"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// Shared test scaffolding for per-provider transform_*_test.go files. Each
// strategy test file builds a slice of transformCase entries and dispatches
// them via runTransformCases. Helpers like timeRef / affectedPkgSlice /
// unaffectedPkgSlice / stringRef live here because they're shape-agnostic and
// used by every provider's expected-output construction.

var timeVal = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
var listing = provider.File{
	Path:      "some",
	Digest:    "123456",
	Algorithm: "sha256",
}

func inputProviderState() provider.State {
	return provider.State{
		Provider:  "osv",
		Version:   12,
		Processor: "vunnel@1.2.3",
		Timestamp: timeVal,
		Listing:   &listing,
	}
}

func expectedProvider() *db.Provider {
	return &db.Provider{
		ID:           "osv",
		Version:      "12",
		Processor:    "vunnel@1.2.3",
		DateCaptured: &timeVal,
		InputDigest:  "sha256:123456",
	}
}

func timeRef(t time.Time) *time.Time {
	return &t
}

func loadFixture(t *testing.T, fixturePath string) []unmarshal.OSVVulnerability {
	t.Helper()

	f, err := os.Open(fixturePath)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, f.Close())
	}()

	entries, err := unmarshal.OSVVulnerabilityEntries(f)
	require.NoError(t, err)
	return entries
}

func affectedPkgSlice(a ...db.AffectedPackageHandle) []any {
	var r []any
	for _, v := range a {
		r = append(r, v)
	}
	return r
}

func unaffectedPkgSlice(u ...db.UnaffectedPackageHandle) []any {
	var r []any
	for _, v := range u {
		r = append(r, v)
	}
	return r
}

func stringRef(s string) *string {
	return &s
}

// transformCase is a per-fixture integration test case: load a real OSV
// record from testdata, run it through Transform, and cmp.Diff the result
// against want.
type transformCase struct {
	name        string
	fixturePath string
	want        []transformers.RelatedEntries
}

// runTransformCases drives a slice of transformCase entries in parallel
// subtests. Each provider's transform_*_test.go file builds its own slice
// and calls this.
func runTransformCases(t *testing.T, tests []transformCase) {
	t.Helper()
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			vulns := loadFixture(tt, test.fixturePath)
			var actual []transformers.RelatedEntries
			for _, vuln := range vulns {
				entries, err := Transform(vuln, inputProviderState())
				require.NoError(tt, err)
				for _, entry := range entries {
					e, ok := entry.Data.(transformers.RelatedEntries)
					require.True(tt, ok)
					actual = append(actual, e)
				}
			}
			if diff := cmp.Diff(test.want, actual); diff != "" {
				tt.Errorf("data entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_extractCVSSInfo covers the CVSS-vector parsing helper. The CVSS format
// regex is shared across providers and has edge cases (invalid prefix, empty,
// non-numeric version) that real fixtures don't reliably exercise.
func Test_extractCVSSInfo(t *testing.T) {
	tests := []struct {
		name        string
		cvss        string
		wantVersion string
		wantVector  string
		wantErr     bool
	}{
		{
			name:        "valid cvss",
			cvss:        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantVersion: "3.1",
			wantVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr:     false,
		},
		{
			name:    "invalid cvss",
			cvss:    "foo:3.1/bar",
			wantErr: true,
		},
		{
			name:    "empty cvss",
			cvss:    "",
			wantErr: true,
		},
		{
			name:    "invalid cvss version",
			cvss:    "CVSS:foo/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			wantErr: true,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			gotVersion, gotVector, err := extractCVSSInfo(test.cvss)
			if (err != nil) != test.wantErr {
				tt.Errorf("extractCVSSInfo() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if gotVersion != test.wantVersion {
				tt.Errorf("extractCVSSInfo() got version = %v, want %v", gotVersion, test.wantVersion)
			}
			if gotVector != test.wantVector {
				tt.Errorf("extractCVSSInfo() got vector = %v, want %v", gotVector, test.wantVector)
			}
		})
	}
}
