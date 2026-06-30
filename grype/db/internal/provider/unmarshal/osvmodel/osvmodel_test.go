package osvmodel

import (
	"encoding/json"
	"testing"
	"time"
)

// TestVulnerabilityUnmarshal pins the JSON-tag wiring on the top-level OSV
// record fields the transformers read. The fields here are exactly the set
// strategies in grype/db/v6/build/transformers/osv depend on — anything
// downstream that pulls another field needs to be added to the struct first
// and to this test second.
//
// The fixture mirrors a real Canonical UBUNTU-CVE record shape: top-level
// Upstream is the load-bearing extension (osv-scanner@v1.9.2 lacked it,
// which is why we own the model now). Withdrawn is the "this CVE was
// retracted" timestamp the ubuntu strategy skips on.
func TestVulnerabilityUnmarshal(t *testing.T) {
	raw := `{
		"schema_version": "1.7.0",
		"id": "UBUNTU-CVE-2023-38545",
		"modified": "2026-04-22T07:45:24Z",
		"published": "2023-10-11T06:00:00Z",
		"withdrawn": "2025-06-23T15:53:49Z",
		"aliases": [],
		"related": [],
		"upstream": ["CVE-2023-38545"],
		"summary": "curl SOCKS5 heap overflow",
		"details": "long description",
		"severity": [
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			{"type": "Ubuntu", "score": "high"}
		],
		"references": [
			{"type": "REPORT", "url": "https://ubuntu.com/security/CVE-2023-38545"},
			{"type": "ADVISORY", "url": "https://ubuntu.com/security/notices/USN-6429-1"}
		],
		"affected": [
			{
				"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "curl", "purl": "pkg:deb/ubuntu/curl@7.81?arch=source&distro=jammy"},
				"ranges": [
					{
						"type": "ECOSYSTEM",
						"events": [{"introduced": "0"}, {"fixed": "7.81.0-1ubuntu1.14"}],
						"database_specific": {
							"anchore": {
								"fixes": [{"version": "7.81.0-1ubuntu1.14", "kind": "advisory", "date": "2023-10-11"}]
							}
						}
					}
				],
				"versions": ["7.81.0-1ubuntu1.13"],
				"ecosystem_specific": {"availability": "No subscription required"},
				"database_specific": {"anchore": {"status": "wont-fix"}}
			}
		],
		"database_specific": {"top_level_extension": "value"}
	}`

	var v Vulnerability
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if v.SchemaVersion != "1.7.0" {
		t.Errorf("SchemaVersion = %q, want 1.7.0", v.SchemaVersion)
	}
	if v.ID != "UBUNTU-CVE-2023-38545" {
		t.Errorf("ID = %q, want UBUNTU-CVE-2023-38545", v.ID)
	}
	if !v.Modified.Equal(time.Date(2026, time.April, 22, 7, 45, 24, 0, time.UTC)) {
		t.Errorf("Modified = %v, unexpected", v.Modified)
	}
	if v.Withdrawn.IsZero() {
		t.Errorf("Withdrawn should have parsed, got zero — withdrawn-skip logic depends on this")
	}
	if got, want := v.Upstream, []string{"CVE-2023-38545"}; !equalStrings(got, want) {
		t.Errorf("Upstream = %v, want %v (this is the field osv-scanner@v1.9.2 lacked)", got, want)
	}
	if v.Summary != "curl SOCKS5 heap overflow" {
		t.Errorf("Summary unexpected: %q", v.Summary)
	}
	if len(v.Severity) != 2 || v.Severity[0].Type != SeverityCVSSV3 {
		t.Errorf("Severity wiring broke: %+v", v.Severity)
	}
	if len(v.References) != 2 || v.References[1].Type != ReferenceAdvisory {
		t.Errorf("References wiring broke: %+v", v.References)
	}

	if len(v.Affected) != 1 {
		t.Fatalf("Affected len = %d, want 1", len(v.Affected))
	}
	a := v.Affected[0]
	if a.Package.Ecosystem != "Ubuntu:22.04:LTS" {
		t.Errorf("Package.Ecosystem = %q, want Ubuntu:22.04:LTS", a.Package.Ecosystem)
	}
	if a.Package.Name != "curl" {
		t.Errorf("Package.Name = %q, want curl", a.Package.Name)
	}
	if a.Package.Purl == "" {
		t.Error("Package.Purl missing — the vunnel/vex distro-label join depends on this")
	}
	if len(a.Ranges) != 1 || a.Ranges[0].Type != RangeEcosystem {
		t.Errorf("Range wiring broke: %+v", a.Ranges)
	}
	if AffectedExtension(a.DatabaseSpecific).Status != "wont-fix" {
		t.Errorf("AffectedExtension.Status = %q, want wont-fix (round-trip through database_specific failed)",
			AffectedExtension(a.DatabaseSpecific).Status)
	}
	if got := RangeExtension(a.Ranges[0].DatabaseSpecific).Fixes; len(got) != 1 || got[0].Version != "7.81.0-1ubuntu1.14" {
		t.Errorf("RangeExtension.Fixes wiring broke: %+v", got)
	}
	// EcosystemSpecific is a free-form map by design — strategies own decoding.
	if a.EcosystemSpecific["availability"] != "No subscription required" {
		t.Errorf("EcosystemSpecific.availability did not round-trip: %v", a.EcosystemSpecific)
	}
	// Top-level database_specific stays as-is too.
	if v.DatabaseSpecific["top_level_extension"] != "value" {
		t.Errorf("top-level database_specific did not round-trip: %v", v.DatabaseSpecific)
	}
}

// TestRangeTypeRoundTrip locks in the unknown-value passthrough behavior.
// OSV admits new range types at the upstream's discretion; we want unknown
// values to round-trip as their string form so the defaultRangeType fallback
// can emit "unknown" rather than coercing into a known type.
func TestRangeTypeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want RangeType
	}{
		{"semver", `"SEMVER"`, RangeSemVer},
		{"ecosystem", `"ECOSYSTEM"`, RangeEcosystem},
		{"git", `"GIT"`, RangeGit},
		{"unknown future value", `"SOMETHING_NEW"`, RangeType("SOMETHING_NEW")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RangeType
			if err := json.Unmarshal([]byte(tt.raw), &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("RangeType = %q, want %q", got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
