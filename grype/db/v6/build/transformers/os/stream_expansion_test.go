package os

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v6"
)

func intRef(i int) *int { return &i }

// --- fixture builders -------------------------------------------------------

// streamAdvisory is a per-stream RHSA that targets a specific RHEL minor (e.g. .el9_2).
func streamAdvisory(id, version string, minor int) unmarshal.OSAdvisory {
	return unmarshal.OSAdvisory{Advisory: id, Version: version, Minor: intRef(minor), Channels: []string{"ga"}}
}

// gaAdvisory is a GA (major-wide) build with no known minor (a bare .elN dist tag). Its
// minor is inferred from EVR ordering during expansion.
func gaAdvisory(id, version string) unmarshal.OSAdvisory {
	return unmarshal.OSAdvisory{Advisory: id, Version: version, Minor: nil, Channels: []string{}}
}

// rhelFixed builds a single-package RHEL vulnerability. topVersion is the record's canonical
// fix; advs are the per-stream advisories (pass none for a plain single-stream record).
func rhelFixed(namespace, pkg, topVersion string, advs ...unmarshal.OSAdvisory) unmarshal.OSVulnerability {
	v := unmarshal.OSVulnerability{}
	v.Vulnerability.Name = "CVE-TEST-0001"
	v.Vulnerability.NamespaceName = namespace
	fi := unmarshal.OSFixedIn{Name: pkg, NamespaceName: namespace, Version: topVersion, VersionFormat: "rpm"}
	if len(advs) > 0 {
		fi.Advisories = advs
	}
	v.Vulnerability.FixedIn = unmarshal.OSFixedIns{fi}
	return v
}

// --- assertion helpers ------------------------------------------------------

// fixByMinor returns pkg's affected fix versions keyed by OS minor ("" is the major-only
// fallback row), asserting there is exactly one row per minor.
func fixByMinor(t *testing.T, afs []db.AffectedPackageHandle, pkg string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range afs {
		if h.Package.Name != pkg {
			continue
		}
		m := h.OperatingSystem.MinorVersion
		require.NotContains(t, out, m, "duplicate affected row for %s minor %q", pkg, m)
		require.Len(t, h.BlobValue.Ranges, 1, "%s minor %q should have exactly one range", pkg, m)
		out[m] = h.BlobValue.Ranges[0].Fix.Version
	}
	require.NotEmpty(t, out, "no affected rows for package %q", pkg)
	return out
}

// assertCopiedToAllMinors asserts pkg was fixed at the same evr on every materialized minor
// row and the major-only fallback -- i.e. a single fix copied verbatim across the whole span.
func assertCopiedToAllMinors(t *testing.T, afs []db.AffectedPackageHandle, pkg, evr string) {
	t.Helper()
	got := fixByMinor(t, afs, pkg)
	require.Contains(t, got, "", "expected a major-only fallback row (minor \"\")")
	require.Greater(t, len(got), 1, "expected the fix to be expanded across multiple minors")
	for minor, fix := range got {
		assert.Equalf(t, evr, fix, "minor %q should carry the copied fix", minor)
	}
}

// assertMinorAssignment asserts pkg's affected rows map exactly onto want: a minor->fixed-EVR
// expectation where "" is the major-only fallback row. It fails on any missing minor, wrong
// fix, or unexpected extra row, so the caller writes the whole intended per-minor picture.
func assertMinorAssignment(t *testing.T, afs []db.AffectedPackageHandle, pkg string, want map[string]string) {
	t.Helper()
	assert.Equal(t, want, fixByMinor(t, afs, pkg))
}

// assertNotAffectedOnAllMinors asserts pkg carries a not-affected (suppressing) handle on
// every materialized minor plus the major-only fallback. This guards the minored-host false
// positive: an affected row expanded to a minor must have a co-located suppression, or a host
// on that minor matches the affected row while the major-only suppression is never consulted.
func assertNotAffectedOnAllMinors(t *testing.T, unafs []db.UnaffectedPackageHandle, pkg string) {
	t.Helper()
	minors := map[string]bool{}
	for _, h := range unafs {
		if h.Package.Name != pkg {
			continue
		}
		require.Len(t, h.BlobValue.Ranges, 1)
		assert.Equal(t, db.NotAffectedFixStatus, h.BlobValue.Ranges[0].Fix.State, "%s minor %q", pkg, h.OperatingSystem.MinorVersion)
		minors[h.OperatingSystem.MinorVersion] = true
	}
	require.Contains(t, minors, "", "expected a major-only fallback not-affected row")
	require.Greater(t, len(minors), 1, "not-affected handle was not expanded across minors")
}

// --- tests ------------------------------------------------------------------

// Test_SingleRHSACopiedToAllMinors: a record with a single fix (no per-minor streams) is
// replicated verbatim onto every minor row, so a host on any minor gets the same verdict it
// would from the stock (unexpanded) major row.
func Test_SingleRHSACopiedToAllMinors(t *testing.T) {
	afs, unafs := getPackages(rhelFixed("rhel:9", "bash", "0:5.1.8-6.el9"))

	require.Empty(t, unafs)
	assertCopiedToAllMinors(t, afs, "bash", "0:5.1.8-6.el9")
}

// Test_MultiRHSAsAssignedToCorrectMinors: fixes shipped on two streams (9.2 and 9.4, nothing
// on 9.3) are assigned by rolling FORWARD -- each minor is governed by the lowest fix at or
// above it (the build that actually reaches a host on that minor). Crucially 9.3, which has
// no build of its own, is judged against the 9.4 fix (not the 9.2 one): a 9.3 host is only
// patched once it takes the 9.4 build. Minors past the last fix, and the major-only fallback,
// take the highest fix.
func Test_MultiRHSAsAssignedToCorrectMinors(t *testing.T) {
	afs, _ := getPackages(rhelFixed("rhel:9", "glibc", "0:2.34-60.el9_4",
		streamAdvisory("RHSA-2024:0002", "0:2.34-40.el9_2", 2),
		streamAdvisory("RHSA-2024:0004", "0:2.34-60.el9_4", 4),
	))

	assertMinorAssignment(t, afs, "glibc", map[string]string{
		"0":  "0:2.34-40.el9_2", // rolls forward to the earliest fix
		"1":  "0:2.34-40.el9_2",
		"2":  "0:2.34-40.el9_2", // 9.2 stream
		"3":  "0:2.34-60.el9_4", // no 9.3 build -> the 9.4 build is what reaches it
		"4":  "0:2.34-60.el9_4", // 9.4 stream
		"5":  "0:2.34-60.el9_4",
		"6":  "0:2.34-60.el9_4",
		"7":  "0:2.34-60.el9_4",
		"8":  "0:2.34-60.el9_4",
		"9":  "0:2.34-60.el9_4",
		"10": "0:2.34-60.el9_4",
		"11": "0:2.34-60.el9_4", // past the last fix -> highest fix
		"":   "0:2.34-60.el9_4", // major-only fallback -> highest fix
	})
}

// Test_LaterGARebaseInferredAsNextMinor: a GA build (null minor) whose EVR outranks the
// highest known stream fix is a genuinely-later rebase; it is inferred onto the next minor
// and governs from there up (including the major fallback), while the known stream minors
// keep their fixes. Covers both the glibc case and a version rebase where the release counter
// reset (so ordering must compare full EVR, not the release integer).
func Test_LaterGARebaseInferredAsNextMinor(t *testing.T) {
	tests := []struct {
		name    string
		vuln    unmarshal.OSVulnerability
		pkg     string
		below   string // fix for minors up to and including the known stream
		knownAt int    // the known stream minor
		rebase  string // inferred GA fix for minors above the known stream
	}{
		{
			name: "glibc GA higher release",
			vuln: rhelFixed("rhel:9", "glibc", "0:2.34-100.el9",
				gaAdvisory("RHBA-2024:2413", "0:2.34-100.el9"),
				streamAdvisory("RHSA-2023:5453", "0:2.34-60.el9_2.7", 2),
			),
			pkg: "glibc", below: "0:2.34-60.el9_2.7", knownAt: 2, rebase: "0:2.34-100.el9",
		},
		{
			name: "webkit rebase with reset release counter",
			vuln: rhelFixed("rhel:9", "webkit2gtk3", "0:2.40.5-1.el9",
				gaAdvisory("RHBA-2024:0100", "0:2.40.5-1.el9"),
				streamAdvisory("RHSA-2024:0101", "0:2.38.5-1.el9_2.3", 2),
			),
			pkg: "webkit2gtk3", below: "0:2.38.5-1.el9_2.3", knownAt: 2, rebase: "0:2.40.5-1.el9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			afs, _ := getPackages(tt.vuln)

			want := map[string]string{}
			for m := 0; m <= rhelMinorSpan["9"]; m++ {
				if m <= tt.knownAt {
					want[strconv.Itoa(m)] = tt.below
				} else {
					want[strconv.Itoa(m)] = tt.rebase // inferred at knownAt+1, governs upward
				}
			}
			want[""] = tt.rebase // major fallback -> highest (the inferred rebase)
			assertMinorAssignment(t, afs, tt.pkg, want)
		})
	}
}

// Test_SupersededGADropped: a GA build whose EVR is at or below a known stream fix is already
// covered by that fix, so it is dropped rather than inferred onto a new minor. Every row then
// carries the pinned stream fix (no lower GA build leaks in, which would be a false negative).
func Test_SupersededGADropped(t *testing.T) {
	afs, _ := getPackages(rhelFixed("rhel:8", "kernel", "0:4.18.0-513.5.1.el8_9",
		gaAdvisory("RHBA-2024:0200", "0:4.18.0-193.el8"), // lower EVR -> superseded
		streamAdvisory("RHSA-2024:0201", "0:4.18.0-513.5.1.el8_9", 9),
	))

	assertCopiedToAllMinors(t, afs, "kernel", "0:4.18.0-513.5.1.el8_9")
}

// Test_NotAffectedCopiedToAllMinors: a not-affected package's suppressing handle is expanded
// to every minor, mirroring the affected expansion. Without this a minored host would match
// an expanded affected row while the lone major-only suppression is never consulted.
func Test_NotAffectedCopiedToAllMinors(t *testing.T) {
	vuln := rhelFixed("rhel:9", "podman", "0") // version "0" => not-affected
	afs, unafs := getPackages(vuln)

	require.Empty(t, afs)
	assertNotAffectedOnAllMinors(t, unafs, "podman")
}

// Test_ModuleQualifierPreservedAcrossMinors: rpm module identity is carried onto every
// expanded minor row, so module-scoped matching still works after expansion.
func Test_ModuleQualifierPreservedAcrossMinors(t *testing.T) {
	vuln := rhelFixed("rhel:8", "postgresql", "0:12.5-1.module+el8.3.0+9042+664538f4")
	vuln.Vulnerability.FixedIn[0].Module = strRef("postgresql:12")

	afs, _ := getPackages(vuln)

	assertCopiedToAllMinors(t, afs, "postgresql", "0:12.5-1.module+el8.3.0+9042+664538f4")
	for _, h := range afs {
		require.NotNil(t, h.BlobValue.Qualifiers)
		require.NotNil(t, h.BlobValue.Qualifiers.RpmModularity)
		assert.Equal(t, "postgresql:12", *h.BlobValue.Qualifiers.RpmModularity, "minor %q", h.OperatingSystem.MinorVersion)
	}
}
