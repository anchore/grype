package os

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v6"
)

func intRef(i int) *int { return &i }

// rowConstraint summarizes an expanded handle as "<minor>=<constraint>" for assertions,
// using "" for the major-only fallback row.
func rowConstraints(handles []db.AffectedPackageHandle) []string {
	var out []string
	for _, h := range handles {
		minor := h.OperatingSystem.MinorVersion
		out = append(out, fmt.Sprintf("%s=%s", minor, h.BlobValue.Ranges[0].Version.Constraint))
	}
	sort.Strings(out)
	return out
}

// TestExpand_AlphaBravo proves the exact per-minor row shape from the worked example:
// fixes at 9.2 (Alpha) and 9.3 (Bravo) yield rows 9.0..9.3 plus a major-only fallback,
// each governed by the largest known fix <= its minor; the fallback uses the highest
// known-minor fix (Bravo), NOT any GA build.
func TestExpand_AlphaBravo(t *testing.T) {
	vuln := unmarshal.OSVulnerability{}
	vuln.Vulnerability.Name = "CVE-9999-0001"
	vuln.Vulnerability.NamespaceName = "rhel:9"
	vuln.Vulnerability.FixedIn = unmarshal.OSFixedIns{
		{
			Name:          "streamtest",
			NamespaceName: "rhel:9",
			Version:       "0:1-3.el9_3",
			VersionFormat: "rpm",
			Advisories: []unmarshal.OSAdvisory{
				{Advisory: "RHSA-9999:0002", Version: "0:1-2.el9_2", Minor: intRef(2), Channels: []string{"ga"}},
				{Advisory: "RHSA-9999:0003", Version: "0:1-3.el9_3", Minor: intRef(3), Channels: []string{"ga"}},
			},
		},
	}

	afs, unafs := getPackages(vuln)
	require.Empty(t, unafs)

	// minors 9.0, 9.1, 9.2, 9.3 + major-only fallback = 5 rows for a 2-stream CVE.
	require.Len(t, afs, 5)

	assert.Equal(t, []string{
		"0=< 0:1-2.el9_2", // 9.0 -> below lowest known minor -> lowest fix (Alpha)
		"1=< 0:1-2.el9_2", // 9.1 -> Alpha
		"2=< 0:1-2.el9_2", // 9.2 -> Alpha
		"3=< 0:1-3.el9_3", // 9.3 -> Bravo
		"=< 0:1-3.el9_3",  // major-only fallback -> highest known-minor fix (Bravo)
	}, rowConstraints(afs))

	// every expanded row is keyed on the same major and channel.
	for _, h := range afs {
		assert.Equal(t, "9", h.OperatingSystem.MajorVersion)
		assert.Equal(t, "", h.OperatingSystem.Channel)
		assert.Equal(t, "redhat", h.OperatingSystem.Name)
	}
}

// TestExpand_GlibcSingleKnownMinor proves the GA null-minor build is now INFERRED (not
// dropped): a single known minor (9.2, -60.el9_2.7) plus a GA -100.el9 whose EVR outranks
// it -> the GA is placed at inferred minor 3 and becomes the major-only fallback, while
// minors 9.0..9.2 stay governed by the 9.2 stream fix (regression guard).
func TestExpand_GlibcSingleKnownMinor(t *testing.T) {
	vuln := unmarshal.OSVulnerability{}
	vuln.Vulnerability.Name = "CVE-2023-4813"
	vuln.Vulnerability.NamespaceName = "rhel:9"
	vuln.Vulnerability.FixedIn = unmarshal.OSFixedIns{
		{
			Name:            "glibc",
			NamespaceName:   "rhel:9",
			Version:         "0:2.34-100.el9",
			VersionFormat:   "rpm",
			VulnerableRange: "< 0:2.34-100.el9",
			Advisories: []unmarshal.OSAdvisory{
				{Advisory: "RHBA-2024:2413", Version: "0:2.34-100.el9", Minor: nil, Channels: []string{}},
				{Advisory: "RHSA-2023:5453", Version: "0:2.34-60.el9_2.7", Minor: intRef(2), Channels: []string{"ga"}},
			},
		},
	}

	afs, _ := getPackages(vuln)

	// minors 9.0, 9.1, 9.2, 9.3(inferred) + major-only fallback = 5 rows.
	require.Len(t, afs, 5)
	assert.Equal(t, []string{
		"0=< 0:2.34-60.el9_2.7",
		"1=< 0:2.34-60.el9_2.7",
		"2=< 0:2.34-60.el9_2.7", // 9.2 governance unchanged (regression guard)
		"3=< 0:2.34-100.el9",    // inferred minor: GA EVR > pinned -> genuinely later
		"=< 0:2.34-100.el9",     // fallback now the inferred GA (highest fix)
	}, rowConstraints(afs))
}

// TestExpand_WebkitRebase guards the "compare EVR not release-int" requirement: pinned
// 2.38.5-1.el9_2.3 (minor 2) + GA 2.40.5-1.el9 (null minor) tie at release int 1, but the
// GA's higher VERSION makes its EVR greater -> it must be inferred at minor 3, NOT dropped.
func TestExpand_WebkitRebase(t *testing.T) {
	vuln := unmarshal.OSVulnerability{}
	vuln.Vulnerability.Name = "CVE-9999-0002"
	vuln.Vulnerability.NamespaceName = "rhel:9"
	vuln.Vulnerability.FixedIn = unmarshal.OSFixedIns{
		{
			Name:          "webkit2gtk3",
			NamespaceName: "rhel:9",
			Version:       "0:2.40.5-1.el9",
			VersionFormat: "rpm",
			Advisories: []unmarshal.OSAdvisory{
				{Advisory: "RHBA-9999:0100", Version: "0:2.40.5-1.el9", Minor: nil, Channels: []string{}},
				{Advisory: "RHSA-9999:0101", Version: "0:2.38.5-1.el9_2.3", Minor: intRef(2), Channels: []string{"ga"}},
			},
		},
	}

	afs, _ := getPackages(vuln)

	// minors 9.0, 9.1, 9.2, 9.3(inferred) + major-only fallback = 5 rows.
	require.Len(t, afs, 5)
	assert.Equal(t, []string{
		"0=< 0:2.38.5-1.el9_2.3",
		"1=< 0:2.38.5-1.el9_2.3",
		"2=< 0:2.38.5-1.el9_2.3",
		"3=< 0:2.40.5-1.el9", // higher VERSION wins despite tied release int
		"=< 0:2.40.5-1.el9",
	}, rowConstraints(afs))
}

// TestExpand_GASuperseded proves a GA null-minor build whose EVR is at/below a pinnable
// fix is dropped (safe, no FN): pinned 4.18.0-513.5.1.el8_9 (minor 9) + GA 4.18.0-193.el8
// (lower EVR) -> the GA is superseded and never materialized.
func TestExpand_GASuperseded(t *testing.T) {
	vuln := unmarshal.OSVulnerability{}
	vuln.Vulnerability.Name = "CVE-9999-0003"
	vuln.Vulnerability.NamespaceName = "rhel:8"
	vuln.Vulnerability.FixedIn = unmarshal.OSFixedIns{
		{
			Name:          "kernel",
			NamespaceName: "rhel:8",
			Version:       "0:4.18.0-513.5.1.el8_9",
			VersionFormat: "rpm",
			Advisories: []unmarshal.OSAdvisory{
				{Advisory: "RHBA-9999:0200", Version: "0:4.18.0-193.el8", Minor: nil, Channels: []string{}},
				{Advisory: "RHSA-9999:0201", Version: "0:4.18.0-513.5.1.el8_9", Minor: intRef(9), Channels: []string{"ga"}},
			},
		},
	}

	afs, _ := getPackages(vuln)

	// minors 8.0..8.9 + major-only fallback = 11 rows; the low GA build appears nowhere.
	require.Len(t, afs, 11)
	for _, h := range afs {
		assert.Equal(t, "< 0:4.18.0-513.5.1.el8_9", h.BlobValue.Ranges[0].Version.Constraint)
	}
}

// TestExpand_SingleStreamUnchanged proves a record with no Advisories (or only null-minor
// advisories) is NOT expanded: it keeps the single major-only handle with the original
// VulnerableRange behavior.
func TestExpand_SingleStreamUnchanged(t *testing.T) {
	vuln := unmarshal.OSVulnerability{}
	vuln.Vulnerability.Name = "CVE-2024-0001"
	vuln.Vulnerability.NamespaceName = "rhel:9"
	vuln.Vulnerability.FixedIn = unmarshal.OSFixedIns{
		{
			Name:          "bash",
			NamespaceName: "rhel:9",
			Version:       "0:5.1.8-6.el9",
			VersionFormat: "rpm",
		},
	}

	afs, _ := getPackages(vuln)
	require.Len(t, afs, 1)
	assert.Equal(t, "", afs[0].OperatingSystem.MinorVersion)
	assert.Equal(t, "< 0:5.1.8-6.el9", afs[0].BlobValue.Ranges[0].Version.Constraint)
}
