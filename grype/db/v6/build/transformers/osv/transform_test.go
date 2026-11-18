package osv

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
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

// Test_normalizeSeverity covers the per-type CVSS handling. CVSS v2 vectors in OSV carry no
// "CVSS:2.0/" prefix (as published by, for example, the Docker Hardened Images feed), so they
// must be recognized by shape rather than by the versioned prefix v3 and v4 vectors use.
func Test_normalizeSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity osvmodel.Severity
		want     db.Severity
		wantErr  bool
	}{
		{
			name:     "bare cvss v2 vector",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV2, Score: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
			want: db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value:  db.CVSSSeverity{Vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N", Version: "2.0"},
			},
		},
		{
			name:     "cvss v2 vector with temporal metrics",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV2, Score: "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C"},
			want: db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value:  db.CVSSSeverity{Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C", Version: "2.0"},
			},
		},
		{
			name:     "cvss v3 vector",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			want: db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value:  db.CVSSSeverity{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", Version: "3.1"},
			},
		},
		{
			name:     "cvss v4 vector",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"},
			want: db.Severity{
				Scheme: db.SeveritySchemeCVSS,
				Value:  db.CVSSSeverity{Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", Version: "4.0"},
			},
		},
		{
			name:     "bare v3 vector is not accepted as v2",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV2, Score: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			wantErr:  true,
		},
		{
			name:     "bare vector under a v3 type",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV3, Score: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
			wantErr:  true,
		},
		{
			name:     "empty cvss v2",
			severity: osvmodel.Severity{Type: osvmodel.SeverityCVSSV2, Score: ""},
			wantErr:  true,
		},
		{
			name:     "non-cvss severity passes through",
			severity: osvmodel.Severity{Type: "Ubuntu", Score: "medium"},
			want:     db.Severity{Scheme: db.UnknownSeverityScheme, Value: "medium"},
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got, err := normalizeSeverity(test.severity)
			if (err != nil) != test.wantErr {
				tt.Fatalf("normalizeSeverity() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				tt.Errorf("normalizeSeverity() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Test_getSeverities covers the ordering of severities. Grype reports the first severity, so
// the newest CVSS version must come first regardless of the order the feed lists them in.
func Test_getSeverities(t *testing.T) {
	v2 := osvmodel.Severity{Type: osvmodel.SeverityCVSSV2, Score: "AV:N/AC:M/Au:N/C:P/I:N/A:N"}
	v30 := osvmodel.Severity{Type: osvmodel.SeverityCVSSV3, Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	v31 := osvmodel.Severity{Type: osvmodel.SeverityCVSSV3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	v4 := osvmodel.Severity{Type: osvmodel.SeverityCVSSV4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
	other := osvmodel.Severity{Type: "Ubuntu", Score: "medium"}

	cvss := func(version, vector string) db.Severity {
		return db.Severity{Scheme: db.SeveritySchemeCVSS, Value: db.CVSSSeverity{Vector: vector, Version: version}}
	}
	wantV2 := cvss("2.0", v2.Score)
	wantV30 := cvss("3.0", v30.Score)
	wantV31 := cvss("3.1", v31.Score)
	wantV4 := cvss("4.0", v4.Score)
	wantOther := db.Severity{Scheme: db.UnknownSeverityScheme, Value: "medium"}

	tests := []struct {
		name string
		vuln unmarshal.OSVVulnerability
		want []db.Severity
	}{
		{
			name: "v3 preferred over v2 regardless of feed order",
			vuln: osvVulnWithSeverities(v2, v31),
			want: []db.Severity{wantV31, wantV2},
		},
		{
			name: "v4 preferred over v3",
			vuln: osvVulnWithSeverities(v31, v4),
			want: []db.Severity{wantV4, wantV31},
		},
		{
			name: "v3.1 preferred over v3.0",
			vuln: osvVulnWithSeverities(v30, v31),
			want: []db.Severity{wantV31, wantV30},
		},
		{
			name: "v2 only",
			vuln: osvVulnWithSeverities(v2),
			want: []db.Severity{wantV2},
		},
		{
			name: "already newest first is unchanged",
			vuln: osvVulnWithSeverities(v4, v31, v2),
			want: []db.Severity{wantV4, wantV31, wantV2},
		},
		{
			name: "non-cvss severities follow cvss severities",
			vuln: osvVulnWithSeverities(other, v2, v31),
			want: []db.Severity{wantV31, wantV2, wantOther},
		},
		{
			name: "affected-level severities are ordered with the record-level ones",
			vuln: unmarshal.OSVVulnerability{
				Severity: []osvmodel.Severity{v2},
				Affected: []osvmodel.Affected{{Severity: []osvmodel.Severity{v4}}},
			},
			want: []db.Severity{wantV4, wantV2},
		},
		{
			name: "no severities",
			vuln: osvVulnWithSeverities(),
			want: nil,
		},
	}
	t.Parallel()
	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			tt.Parallel()
			got, err := getSeverities(test.vuln)
			require.NoError(tt, err)
			if diff := cmp.Diff(test.want, got); diff != "" {
				tt.Errorf("getSeverities() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func osvVulnWithSeverities(severities ...osvmodel.Severity) unmarshal.OSVVulnerability {
	return unmarshal.OSVVulnerability{Severity: severities}
}
