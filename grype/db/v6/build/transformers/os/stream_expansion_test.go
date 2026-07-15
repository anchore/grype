package os

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
)

func intRef(i int) *int { return &i }

// --- fixture builders -------------------------------------------------------

// streamAdvisory is a per-stream RHSA that targets a specific RHEL minor (e.g. .el9_2).
func streamAdvisory(id, version string, minor int) unmarshal.OSAdvisory {
	return unmarshal.OSAdvisory{Advisory: id, Version: version, Minor: intRef(minor), Channels: []string{"ga"}}
}

// gaAdvisory is a GA (major-wide) build with no known minor (a bare .elN dist tag); it is
// not tied to any specific stream.
func gaAdvisory(id, version string) unmarshal.OSAdvisory {
	return unmarshal.OSAdvisory{Advisory: id, Version: version, Minor: nil, Channels: []string{}}
}

// rhelFixed builds a single-package RHEL vulnerability. topVersion is the record's canonical
// fix; advs are the per-stream advisories (pass none for a plain single-stream record). The
// record's top-level VendorAdvisory is derived from the highest-versioned advisory in advs --
// mirroring how RHEL records carry the latest build's errata at the top level.
func rhelFixed(namespace, pkg, topVersion string, advs ...unmarshal.OSAdvisory) unmarshal.OSVulnerability {
	v := unmarshal.OSVulnerability{}
	v.Vulnerability.Name = "CVE-TEST-0001"
	v.Vulnerability.NamespaceName = namespace
	fi := unmarshal.OSFixedIn{Name: pkg, NamespaceName: namespace, Version: topVersion, VersionFormat: "rpm"}
	if len(advs) > 0 {
		fi.Advisories = advs
	}
	if top, ok := highestVersionedAdvisory(advs); ok {
		fi.VendorAdvisory.AdvisorySummary = []struct {
			ID   string `json:"ID"`
			Link string `json:"Link"`
		}{
			{ID: top.Advisory, Link: "https://access.redhat.com/errata/" + top.Advisory},
		}
	}
	v.Vulnerability.FixedIn = unmarshal.OSFixedIns{fi}
	return v
}

// highestVersionedAdvisory returns the advisory in advs with the highest RPM version, so a
// fixture's top-level advisory reflects the latest build shipped for the record.
func highestVersionedAdvisory(advs []unmarshal.OSAdvisory) (best unmarshal.OSAdvisory, found bool) {
	for _, adv := range advs {
		if !found {
			best, found = adv, true
			continue
		}
		if cmp, err := version.New(adv.Version, version.RpmFormat).Compare(version.New(best.Version, version.RpmFormat)); err == nil && cmp > 0 {
			best = adv
		}
	}
	return best, found
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

// constraintByMinor returns pkg's per-minor range CONSTRAINT keyed by OS minor ("" = major
// fallback), asserting exactly one row per minor.
func constraintByMinor(t *testing.T, afs []db.AffectedPackageHandle, pkg string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range afs {
		if h.Package.Name != pkg {
			continue
		}
		m := h.OperatingSystem.MinorVersion
		require.NotContains(t, out, m, "duplicate row for %s minor %q", pkg, m)
		require.Len(t, h.BlobValue.Ranges, 1, "%s minor %q should have exactly one range", pkg, m)
		out[m] = h.BlobValue.Ranges[0].Version.Constraint
	}
	require.NotEmpty(t, out, "no affected rows for package %q", pkg)
	return out
}

// advisoryIDByMinor returns pkg's per-minor fix RHSA id (from the fix's first advisory
// reference) keyed by OS minor ("" = major fallback); "" when a row carries no reference.
func advisoryIDByMinor(t *testing.T, afs []db.AffectedPackageHandle, pkg string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, h := range afs {
		if h.Package.Name != pkg {
			continue
		}
		id := ""
		if r := h.BlobValue.Ranges[0]; r.Fix != nil && r.Fix.Detail != nil && len(r.Fix.Detail.References) > 0 {
			id = r.Fix.Detail.References[0].ID
		}
		out[h.OperatingSystem.MinorVersion] = id
	}
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
//
// Real data: RHEL 9 CVE-2006-20001 (httpd), a single fix 0:2.4.53-7.el9_1.1 shipped by
// RHSA-2023:0970 with no per-minor Advisories list -- the common single-stream shape.
func Test_SingleRHSACopiedToAllMinors(t *testing.T) {
	afs, unafs := getPackages(rhelFixed("rhel:9", "httpd", "0:2.4.53-7.el9_1.1"))
	require.Empty(t, unafs)
	assertCopiedToAllMinors(t, afs, "httpd", "0:2.4.53-7.el9_1.1")
}

// Test_MultiRHSAsAssignedToCorrectMinors: a per-stream RHSA fix is pinned ONLY to the exact
// minor it targets (9.1 and 9.3 here); it is not rolled onto adjacent minors. Every other
// minor -- the gaps (9.0, 9.2) and everything past the last stream, plus the major-only
// fallback -- carries the record's base fix (its canonical top-level version), which here is
// the 9.3 GA build. So the two stream minors cite their own RHSA and every other row carries
// the base fix with no per-stream advisory reference.
//
// Real data: RHEL 9 CVE-2022-50536 (kernel), same-base multi-minor with no VulnerableRange.
// RHSA-2022:8267 ships 0:5.14.0-162.6.1.el9_1 on 9.1 (minor 1); RHSA-2023:6583 ships
// 0:5.14.0-362.8.1.el9_3 on 9.3 (minor 3). Nothing on 9.2 -> the gap falls to the base fix.
func Test_MultiRHSAsAssignedToCorrectMinors(t *testing.T) {
	fixed := rhelFixed("rhel:9", "kernel", "0:5.14.0-362.8.1.el9_3",
		streamAdvisory("RHSA-2022:8267", "0:5.14.0-162.6.1.el9_1", 1),
		streamAdvisory("RHSA-2023:6583", "0:5.14.0-362.8.1.el9_3", 3),
	)

	afs, _ := getPackages(fixed)

	assertMinorAssignment(t, afs, "kernel", map[string]string{
		"0":  "0:5.14.0-362.8.1.el9_3", // no 9.0 stream -> base fix (the 9.3 GA build)
		"1":  "0:5.14.0-162.6.1.el9_1", // 9.1 stream
		"2":  "0:5.14.0-362.8.1.el9_3", // no 9.2 stream -> base fix
		"3":  "0:5.14.0-362.8.1.el9_3", // 9.3 stream
		"4":  "0:5.14.0-362.8.1.el9_3",
		"5":  "0:5.14.0-362.8.1.el9_3",
		"6":  "0:5.14.0-362.8.1.el9_3",
		"7":  "0:5.14.0-362.8.1.el9_3",
		"8":  "0:5.14.0-362.8.1.el9_3",
		"9":  "0:5.14.0-362.8.1.el9_3",
		"10": "0:5.14.0-362.8.1.el9_3", // past the last stream -> base fix
		"":   "0:5.14.0-362.8.1.el9_3", // major-only fallback -> base fix
	})

	// a stream minor cites its own RHSA; every base-fix row cites the record's top-level advisory.
	assert.Equal(t, map[string]string{
		"0": "RHSA-2023:6583", "1": "RHSA-2022:8267",
		"2": "RHSA-2023:6583", "3": "RHSA-2023:6583", "4": "RHSA-2023:6583", "5": "RHSA-2023:6583",
		"6": "RHSA-2023:6583", "7": "RHSA-2023:6583", "8": "RHSA-2023:6583",
		"9": "RHSA-2023:6583", "10": "RHSA-2023:6583",
		"": "RHSA-2023:6583",
	}, advisoryIDByMinor(t, afs, "kernel"))

	// and each reference is a proper Red Hat errata link tagged as an advisory.
	for _, h := range afs {
		ref := h.BlobValue.Ranges[0].Fix.Detail.References[0]
		assert.Equal(t, "https://access.redhat.com/errata/"+ref.ID, ref.URL)
		assert.Contains(t, ref.Tags, db.AdvisoryReferenceTag)
	}
}

// Test_SupersededGADropped: a GA build (null minor) never becomes a row's fix -- only the
// pinned stream minors carry their own fix, and every other minor carries the base fix. A
// lower GA build must not leak in as a fix (which would be a false negative).
//
// Real data: RHEL 6 CVE-2018-3639 (kernel), no VulnerableRange (so it takes the per-minor path).
// RHSA-2018:1651 pins 0:2.6.32-696.30.1.el6 on 6.9 (minor 9); RHSA-2018:2164 pins
// 0:2.6.32-754.2.1.el6 on 6.10 (minor 10); RHSA-2018:1854 is a GA build 0:2.6.32-754.el6 with a
// null minor. Only 6.9 and 6.10 pin their stream fixes; every other minor takes the base fix
// (0:2.6.32-754.2.1.el6), and the GA build never appears.
func Test_SupersededGADropped(t *testing.T) {
	afs, _ := getPackages(rhelFixed("rhel:6", "kernel", "0:2.6.32-754.2.1.el6",
		gaAdvisory("RHSA-2018:1854", "0:2.6.32-754.el6"), // lower EVR than the 6.10 fix -> superseded
		streamAdvisory("RHSA-2018:1651", "0:2.6.32-696.30.1.el6", 9),
		streamAdvisory("RHSA-2018:2164", "0:2.6.32-754.2.1.el6", 10),
	))

	// the dropped GA build must not appear as any row's fix -- otherwise a host past its stream
	// fix but below the (lower) GA build would be wrongly cleared.
	got := fixByMinor(t, afs, "kernel")
	for minor, fix := range got {
		assert.NotEqualf(t, "0:2.6.32-754.el6", fix, "superseded GA build leaked onto minor %q", minor)
	}

	assertMinorAssignment(t, afs, "kernel", map[string]string{
		"0":  "0:2.6.32-754.2.1.el6", // no 6.0 stream -> base fix
		"1":  "0:2.6.32-754.2.1.el6",
		"2":  "0:2.6.32-754.2.1.el6",
		"3":  "0:2.6.32-754.2.1.el6",
		"4":  "0:2.6.32-754.2.1.el6",
		"5":  "0:2.6.32-754.2.1.el6",
		"6":  "0:2.6.32-754.2.1.el6",
		"7":  "0:2.6.32-754.2.1.el6",
		"8":  "0:2.6.32-754.2.1.el6",
		"9":  "0:2.6.32-696.30.1.el6", // 6.9 stream
		"10": "0:2.6.32-754.2.1.el6",  // 6.10 stream
		"":   "0:2.6.32-754.2.1.el6",  // major-only fallback -> base fix
	})
}

// Test_NotAffectedCopiedToAllMinors: a not-affected package's suppressing handle is expanded
// to every minor, mirroring the affected expansion. Without this a minored host would match
// an expanded affected row while the lone major-only suppression is never consulted.
// Real data: RHEL 9 CVE-2002-0059 (zlib) is a real not-affected record -- a single FixedIn with
// Version "0" and no advisory, i.e. RHEL 9's zlib is not affected.
func Test_NotAffectedCopiedToAllMinors(t *testing.T) {
	vuln := rhelFixed("rhel:9", "zlib", "0") // version "0" => not-affected
	afs, unafs := getPackages(vuln)

	require.Empty(t, afs)
	assertNotAffectedOnAllMinors(t, unafs, "zlib")
}

// Test_ModuleQualifierPreservedAcrossMinors: rpm module identity is carried onto every
// expanded minor row, so module-scoped matching still works after expansion.
// Real data: RHEL 8 CVE-2007-4559 (python39 module). RHSA-2023:7034 ships
// 0:3.9.18-1.module+el8.9.0+20024+793d7211 for the python39:3.9 module stream -- a single
// module-scoped fix that must keep its module qualifier on every expanded minor row.
func Test_ModuleQualifierPreservedAcrossMinors(t *testing.T) {
	vuln := rhelFixed("rhel:8", "python39", "0:3.9.18-1.module+el8.9.0+20024+793d7211")
	vuln.Vulnerability.FixedIn[0].Module = strRef("python39:3.9")

	afs, _ := getPackages(vuln)

	assertCopiedToAllMinors(t, afs, "python39", "0:3.9.18-1.module+el8.9.0+20024+793d7211")
	for _, h := range afs {
		require.NotNil(t, h.BlobValue.Qualifiers)
		require.NotNil(t, h.BlobValue.Qualifiers.RpmModularity)
		assert.Equal(t, "python39:3.9", *h.BlobValue.Qualifiers.RpmModularity, "minor %q", h.OperatingSystem.MinorVersion)
	}
}

// Test_MultiUpstreamBase_KeepsDisjointRange uses real data: RHEL 8 CVE-2020-0543 (microcode_ctl),
// fixed on two upstream bases -- RHSA-2020:2431 (base 20191115, el8_2) and RHSA-2021:3027 (base
// 20210216, el8_4) -- which vunnel emits as a disjoint VulnerableRange plus a two-entry Advisories
// list. The expansion must NOT collapse this to a single "< fix" per minor (that would flag
// a host still on the 20191115 base, carrying its own el8_2 fix, against the 20210216 build).
// Instead it must (a) stay COMPLETE: present on every minor row + major fallback (so a minored host
// resolving to a per-minor row still sees the package), and (b) stay CORRECT: every row carries the
// disjoint VulnerableRange verbatim, not a single governing fix.
func Test_MultiUpstreamBase_KeepsDisjointRange(t *testing.T) {
	const vulnRange = "< 4:20191115-4.20200602.2.el8_2 || >= 4:20210216, < 4:20210216-1.20210608.1.el8_4"
	vuln := rhelFixed("rhel:8", "microcode_ctl", "4:20210216-1.20210608.1.el8_4",
		streamAdvisory("RHSA-2020:2431", "4:20191115-4.20200602.2.el8_2", 2),
		streamAdvisory("RHSA-2021:3027", "4:20210216-1.20210608.1.el8_4", 4),
	)
	vuln.Vulnerability.FixedIn[0].VulnerableRange = vulnRange // multi-upstream-base marker

	afs, _ := getPackages(vuln)

	got := constraintByMinor(t, afs, "microcode_ctl")
	require.Len(t, got, rhelMinorSpan["8"]+2) // completeness: 8.0..span + major fallback ("")
	for minor, c := range got {
		assert.Equalf(t, vulnRange, c, "minor %q must carry the disjoint VulnerableRange, not a collapsed single fix", minor)
	}
}
