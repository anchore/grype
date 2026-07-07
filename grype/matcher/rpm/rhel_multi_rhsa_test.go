package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The fixture (testdata/rhel-multi-rhsa) holds REAL Red Hat records (extracted verbatim from
// the vunnel results DB, scoped to the package under test - no synthetic vulnerability data).
// dbtest runs the real grype-db transform over them, so these tests validate the whole
// vunnel -> grype-db -> grype matching path, not hand-built v6 constraints. The records:
//
//   - CVE-2024-8088 (python3.9): the multi-upstream-base record - two RHSAs fixing distinct
//     upstream bases reduced to one record whose VulnerableRange partitions the streams:
//     < 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9
//   - CVE-2020-0543 (microcode_ctl): multi-base AND per-stream Advisories together.
//   - CVE-2023-4813 (glibc), CVE-2022-50536 (kernel), CVE-2015-7979 (ntp),
//     CVE-2018-3639 (el6 kernel): per-minor `Advisories` records that the v6 OS transformer
//     expands into per-minor operating_system rows (see TestRpmPerMinorExpansion_* below).
//   - CVE-2017-17095 (libtiff): a plain single-stream package for the cumulative
//     completeness guard.
//
// See https://access.redhat.com/security/cve/cve-2024-8088#cve-affected-packages

// rhelPython39Host builds the package shape the matcher receives for a RHEL host:
// the python3 binary RPM plus an upstream pointer to its python3.9 source RPM, so the
// matcher's source-indirection path engages (the RHEL data is keyed on the source RPM).
func rhelPython39Host(d *distro.Distro, version string, id pkg.ID) pkg.Package {
	return dbtest.NewPackage("python3", version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithUpstream("python3.9", version).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

func TestRpmMultiRHSA_CVE2024_8088_PartitionedStreams(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel94 := distro.New(distro.RedHat, "9.4", "")

			cases := []struct {
				name       string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "at lower-stream fix (RHSA-2024:6163)",
					version:    "3.9.18-3.el9_4.5",
					vulnerable: false,
					why:        "host carries the 9.4 Z-stream backport; < 3.9.19 so it falls into no clause",
				},
				{
					name:       "below lower-stream fix",
					version:    "3.9.18-3.el9_4.4",
					vulnerable: true,
					why:        "one Z-stream patch behind the 9.4 fix - genuinely vulnerable",
				},
				{
					name:       "above lower-stream fix, still in 3.9.18 line",
					version:    "3.9.18-10.el9_4",
					vulnerable: false,
					why:        "above the 9.4 fix, still < 3.9.19 - not vulnerable",
				},
				{
					name:       "in 3.9.19 stream below upper-stream fix",
					version:    "3.9.19-1.el9",
					vulnerable: true,
					why:        ">= 3.9.19 and < 3.9.19-8.el9 - pre-RHSA-2024:9371 build is vulnerable",
				},
				{
					name:       "at upper-stream fix (RHSA-2024:9371)",
					version:    "3.9.19-8.el9",
					vulnerable: false,
					why:        "host carries the 9.5 GA fix - not vulnerable",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("python3-" + c.version)
					p := rhelPython39Host(rhel94, c.version, pkgID)
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2024-8088").
							SelectDetailByType(match.ExactIndirectMatch).
							AsDistroSearch()
					} else {
						// not vulnerable: the owned python3 binary yields a "Distro Not
						// Vulnerable" ownership ignore rather than a match.
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-8088").
							ForPackage(pkgID).
							WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
					}
				})
			}
		})
}

// The fix metadata and folded advisories should survive the transform onto the match.
func TestRpmMultiRHSA_CVE2024_8088_FixAndAdvisories(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := rhelPython39Host(distro.New(distro.RedHat, "9.4", ""), "3.9.18-3.el9_4.4", pkg.ID("python3"))

			sf := db.Match(t, &matcher, p).SelectMatch("CVE-2024-8088")
			// canonical fix is the newest stream's build; both RHSAs are surfaced.
			sf.HasFix(vulnerability.FixStateFixed, "0:3.9.19-8.el9").
				HasAdvisories("RHSA-2024:9371", "RHSA-2024:6163")
			sf.SelectDetailByType(match.ExactIndirectMatch).AsDistroSearch()
		})
}

// A host on an older base than either fix (e.g. a 9.2 build that never received a
// targeted backport for this CVE) is below the lowest stream's fix and must stay
// flagged - phase 1 must not over-suppress.
func TestRpmMultiRHSA_CVE2024_8088_OlderBaseStillFlagged(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := rhelPython39Host(distro.New(distro.RedHat, "9.2", ""), "3.9.16-1.el9_2.5", pkg.ID("python3"))

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-8088").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

// TestRpmMultiRHSA_CVE2020_0543_MultiBaseWithAdvisories is the belt-and-braces case for
// the transformer's hasVulnerableRange gate: microcode_ctl carries BOTH a disjoint
// multi-upstream-base VulnerableRange AND per-stream `Advisories` (RHSA-2020:2431 fixing
// the el8_2 base 4:20191115 at minor 2, RHSA-2021:3027 fixing the el8_4 base 4:20210216 at
// minor 4). Per-minor roll-forward CANNOT represent two disjoint bases, so the transformer
// must keep the VulnerableRange (baseRanges) on every minor row rather than collapsing to a
// single `< canonical` bound. If it collapsed, a host on the older el8_2 base carrying its
// own fix would sort below the el8_4 canonical build and be FALSE-POSITIVE'd.
//
// microcode_ctl's binary name equals its source RPM, so the matcher's direct path engages.
// See https://access.redhat.com/security/cve/CVE-2020-0543
func TestRpmMultiRHSA_CVE2020_0543_MultiBaseWithAdvisories(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2020-0543").
		Run(func(t *testing.T, db *dbtest.DB) {
			cases := []struct {
				name       string
				minor      string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "8.2 host at its own el8_2 fix (RHSA-2020:2431)",
					minor:      "8.2",
					version:    "4:20191115-4.20200602.2.el8_2",
					vulnerable: false,
					why:        "carries the el8_2 base fix; not < el8_2 base and not in the el8_4 clause - the gate's FP guard",
				},
				{
					name:       "8.2 host below its el8_2 fix",
					minor:      "8.2",
					version:    "4:20191115-4.20200602.1.el8_2",
					vulnerable: true,
					why:        "one build behind the el8_2 fix; < 4:20191115-4.20200602.2.el8_2 - clause A",
				},
				{
					// The case that only the gate gets right. minor 3 has no fix of its
					// own, so per-minor roll-forward would govern it by the el8_4 canonical
					// (< 4:20210216-1.20210608.1.el8_4) and FALSE-POSITIVE this host, whose
					// el8_2-base build sorts below that canonical. The disjoint range keeps
					// it correctly clean: not < the el8_2 base, and not in the el8_4 clause.
					name:       "8.3 gap-minor host carrying the el8_2 base build",
					minor:      "8.3",
					version:    "4:20191115-4.20200602.2.el8_2",
					vulnerable: false,
					why:        "older-base build is fixed for its base; collapse would wrongly flag it against the el8_4 canonical",
				},
				{
					name:       "8.4 host at its own el8_4 fix (RHSA-2021:3027)",
					minor:      "8.4",
					version:    "4:20210216-1.20210608.1.el8_4",
					vulnerable: false,
					why:        "carries the el8_4 rebase fix; not < the el8_4 canonical build",
				},
				{
					name:       "8.4 host on the el8_4 base below its fix",
					minor:      "8.4",
					version:    "4:20210216-1.20210510.1.el8_4",
					vulnerable: true,
					why:        ">= 4:20210216 and < 4:20210216-1.20210608.1.el8_4 - clause B",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					d := distro.New(distro.RedHat, c.minor, "")
					matcher := Matcher{}
					pkgID := pkg.ID("microcode_ctl-" + c.minor + "-" + c.version)
					p := dbtest.NewPackage("microcode_ctl", c.version, syftPkg.RpmPkg).
						WithID(pkgID).
						WithDistro(d).
						WithMetadata(pkg.RpmMetadata{Epoch: intPtr(4)}).
						Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2020-0543").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2020-0543")
					}
				})
			}
		})
}

// TestRpmNotAffected_MinoredHostGetsSuppressingIgnore guards the not-affected side of the
// per-minor expansion (the mariadb-class false positive). CVE-2021-27928 declares the
// mariadb:10.5 module stream NOT affected (a real Version "0" record) while mariadb:10.3 has
// a real fix (RHSA-2021:1242). The affected rows are expanded per-minor, so the suppressing
// not-affected handle MUST be expanded to the same minors - otherwise a minored host resolves
// to a per-minor row where the lone major-only suppression is never consulted, leaking the
// disclosure back as a false positive.
//
// A RHEL 8.6 host on the not-affected 10.5 stream must therefore (a) not be flagged and (b)
// carry the "Distro Not Vulnerable" ignore that does the suppressing.
//
// Belt-and-braces: this ignore was verified to VANISH for the 8.6 host when
// expandUnaffectedHandles is forced back to a single major-only handle (the pre-fix
// behavior), confirming the assertion actually exercises the per-minor unaffected expansion.
func TestRpmNotAffected_MinoredHostGetsSuppressingIgnore(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2021-27928").
		Run(func(t *testing.T, db *dbtest.DB) {
			// mariadb from the not-affected 10.5 module stream, on a minored 8.6 host.
			p := dbtest.NewPackage("mariadb", "3:10.5.16-1.module+el8.6.0+15522+7adc332a", syftPkg.RpmPkg).
				WithID(pkg.ID("mariadb-10.5")).
				WithDistro(distro.New(distro.RedHat, "8.6", "")).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(3), ModularityLabel: strPtr("mariadb:10.5:8060020220715055054:1e6a3387")}).
				Build()

			db.Match(t, &Matcher{}, p).
				Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2021-27928")
		})
}

// TestRpmCumulativeCompleteness_MinoredHostSeesBothPackages guards the cross-package
// completeness invariant. grype resolves a host to its single most-specific OS row and does
// NOT union in the major-only row (operating_system_store searchForOSExactVersions). So once
// ANY record materializes a per-minor row for rhel:9 (here the multi-stream glibc record
// creates rhel 9.2), a 9.2 host resolves to that row and can only see packages present ON
// it. A plain single-stream package (libtiff, one GA RHSA, no per-minor Advisories) must
// therefore be replicated onto every minor row too - if the transformer only expanded
// multi-stream packages, libtiff would live solely on the major-only row and a 9.2 host
// would silently miss it (a false negative).
//
// Belt-and-braces: this was verified to FAIL for the libtiff case (only) when the
// transformer's non-per-minor groups are forced back to the single major-only handle, while
// the multi-stream glibc case keeps matching - exactly the sparse-row shadow FN.
func TestRpmCumulativeCompleteness_MinoredHostSeesBothPackages(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel92 := distro.New(distro.RedHat, "9.2", "")

			t.Run("single-stream libtiff seen at the minor row", func(t *testing.T) {
				// below the GA fix 0:4.4.0-10.el9; only visible on rhel 9.2 if the
				// single-stream package was expanded across minors (cumulative).
				version := "0:4.4.0-9.el9"
				matcher := Matcher{}
				p := rhelStreamHost("libtiff", rhel92, version, pkg.ID("libtiff-"+version))
				db.Match(t, &matcher, p).
					SelectMatch("CVE-2017-17095").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			t.Run("multi-stream glibc seen at the same minor row", func(t *testing.T) {
				// the record that caused rhel 9.2 to exist; below its 9.2 stream fix.
				version := "0:2.34-60.el9_2.1"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", rhel92, version, pkg.ID("glibc-"+version))
				db.Match(t, &matcher, p).
					SelectMatch("CVE-2023-4813").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})
		})
}

// Server-side stream-affinity (per-minor row expansion) tests.
//
// These prove that an UNMODIFIED (stock main) rpm.Matcher produces correct minor-affine
// matching, purely because the v6 OS transformer expanded each record's per-stream
// `Advisories` list into per-minor operating_system rows (each carrying the fix that
// governs that minor) plus a major-only fallback row. The matcher is never touched; the
// only moving parts are the OS unmarshal struct (which now reads vunnel's per-stream
// `Advisories`) and the OS transformer's per-minor expansion. The assertions run the
// real vunnel -> grype-db -> grype path via the dbtest harness; each test scopes to its
// own CVE (SelectOnly) but the whole fixture is co-resident in the DB, so cross-record
// interference would still surface.

// rhelStreamHost builds a plain RHEL binary RPM whose name equals the source RPM the
// RHEL data is keyed on, so the matcher's direct path engages (no source indirection).
func rhelStreamHost(name string, d *distro.Distro, version string, id pkg.ID) pkg.Package {
	return dbtest.NewPackage(name, version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

// TestRpmPerMinorExpansion_KernelRollForwardGap exercises the real roll-forward-across-a-gap
// record (CVE-2022-50536, kernel): fixes on 9.1 (RHSA-2022:8267, 0:5.14.0-162.6.1.el9_1) and
// 9.3 (RHSA-2023:6583, 0:5.14.0-362.8.1.el9_3), nothing on 9.2. The transformer pins each
// minor to the fix that governs it by rolling FORWARD: 9.2 has no build of its own, so it is
// judged against the reachable 9.3 build. Rolling backward would clear a 9.2 host above the
// 9.1 build but below the applicable 9.3 build - a false negative. Each vulnerable host also
// surfaces the RHSA that governs its minor (asserted via WithAdvisoryLink).
func TestRpmPerMinorExpansion_KernelRollForwardGap(t *testing.T) { //nolint:funlen // table-driven minor-affinity cases
	const (
		rhsa91 = "RHSA-2022:8267"
		rhsa93 = "RHSA-2023:6583"
		link91 = "https://access.redhat.com/errata/RHSA-2022:8267"
		link93 = "https://access.redhat.com/errata/RHSA-2023:6583"
		fix91  = "0:5.14.0-162.6.1.el9_1"
		fix93  = "0:5.14.0-362.8.1.el9_3"
	)
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2022-50536").
		Run(func(t *testing.T, db *dbtest.DB) {
			cases := []struct {
				name        string
				minor       string
				version     string
				vulnerable  bool
				fixVersion  string
				advisory    string
				advisoryURL string
				why         string
			}{
				{
					name: "9.1 host below its own fix", minor: "9.1",
					version: "0:5.14.0-162.el9_1", vulnerable: true,
					fixVersion: fix91, advisory: rhsa91, advisoryURL: link91,
					why: "minor 1 governed by < 162.6.1.el9_1; the initial 9.1 GA kernel is below it",
				},
				{
					name: "9.1 host at its own fix", minor: "9.1",
					version: fix91, vulnerable: false,
					why: "carries the 9.1 fix exactly",
				},
				{
					name: "9.2 gap host rolls forward to the 9.3 fix", minor: "9.2",
					version: "0:5.14.0-284.11.1.el9_2", vulnerable: true,
					fixVersion: fix93, advisory: rhsa93, advisoryURL: link93,
					why: "no 9.2 build; judged against the reachable 9.3 fix. roll-backward would false-negative this 9.2 kernel",
				},
				{
					name: "9.3 host below its own fix", minor: "9.3",
					version: "0:5.14.0-300.el9_3", vulnerable: true,
					fixVersion: fix93, advisory: rhsa93, advisoryURL: link93,
					why: "minor 3 governed by < 362.8.1.el9_3",
				},
				{
					name: "9.3 host at its own fix", minor: "9.3",
					version: fix93, vulnerable: false,
					why: "carries the 9.3 fix exactly",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					d := distro.New(distro.RedHat, c.minor, "")
					matcher := Matcher{}
					p := rhelStreamHost("kernel", d, c.version, pkg.ID("kernel-"+c.minor+"-"+c.version))
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2022-50536").
							HasFix(vulnerability.FixStateFixed, c.fixVersion).
							WithAdvisoryLink(c.advisory, c.advisoryURL).
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2022-50536")
					}
				})
			}
		})
}

// TestRpmPerMinorExpansion_GlibcMinorNull is the real-shape bug case (CVE-2023-4813).
// The record carries a GA RHBA -100.el9 (Minor=null) plus a 9.2 stream RHSA -60.el9_2.7
// (Minor=2). The GA's EVR outranks the stream fix, so the transformer INFERS its minor as
// 3 (max pinned + 1) and materializes it (governing minor 3+ and the major-only fallback),
// closing the false negative for hosts above the pinned minor. Meanwhile minor-2
// governance is unchanged: a 9.2 host past its own stream fix must still NOT be flagged,
// and crucially NOT against the GA -100.el9 build.
func TestRpmPerMinorExpansion_GlibcMinorNull(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel92 := distro.New(distro.RedHat, "9.2", "")

			t.Run("9.2 host past its stream fix", func(t *testing.T) {
				// regression guard: minor-2 governance unchanged by GA inference.
				version := "0:2.34-60.el9_2.14"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", rhel92, version, pkg.ID("glibc-"+version))
				db.Match(t, &matcher, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2023-4813")
			})

			t.Run("9.2 host below its stream fix", func(t *testing.T) {
				version := "0:2.34-60.el9_2.1"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", rhel92, version, pkg.ID("glibc-"+version))
				db.Match(t, &matcher, p).
					SelectMatch("CVE-2023-4813").
					HasFix(vulnerability.FixStateFixed, "0:2.34-60.el9_2.7").
					WithAdvisoryLink("RHSA-2023:5453", "https://access.redhat.com/errata/RHSA-2023:5453").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			t.Run("9.5 host below the inferred GA fix", func(t *testing.T) {
				// the closed FN: a minor ABOVE the highest pinned (9.2), running a build
				// below the GA -100.el9 fix but above the 9.2 fix -> now VULNERABLE
				// (governed by the inferred minor-3+ row < 0:2.34-100.el9). Before the
				// inference this host was cleared (the GA build was dropped).
				rhel95 := distro.New(distro.RedHat, "9.5", "")
				version := "0:2.34-90.el9"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", rhel95, version, pkg.ID("glibc-"+version))
				db.Match(t, &matcher, p).
					SelectMatch("CVE-2023-4813").
					HasFix(vulnerability.FixStateFixed, "0:2.34-100.el9").
					WithAdvisoryLink("RHBA-2024:2413", "https://access.redhat.com/errata/RHBA-2024:2413").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})
		})
}

// TestRpmPerMinorExpansion_SameBaseUnderEUS runs the flagship same-base case (CVE-2023-4813,
// glibc, same record as TestRpmPerMinorExpansion_GlibcMinorNull) under a 9.2+eus host, so it
// exercises the redhatEUSMatches two-fetch path -- unchanged in this branch -- against the
// expanded per-minor rows. Real RHEL images report extendedSupport=true and route through the
// EUS path, not standardMatches, so a channel-less distro alone would leave the live-host
// behavior unpinned. The EUS disclosure fetch is channel-less and lands on the vanilla
// rhel:9.2 row, so an EUS host is judged against its own stream's fix exactly like a GA host.
func TestRpmPerMinorExpansion_SameBaseUnderEUS(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			eus92 := newEUSDistro("9.2")

			t.Run("9.2+eus host past its stream fix", func(t *testing.T) {
				// the OSE false positive: glibc 2.34-60.el9_2.14 carries its own stream's
				// RHSA-2023:5453 fix (0:2.34-60.el9_2.7) but EVR-sorts below the GA
				// 0:2.34-100.el9 build, so pre-expansion it was flagged. On the EUS path
				// the 9.2-row disclosure is dropped at fetch (OnlyVulnerableVersions) and
				// redhatEUSMatches returns early, so unlike the GA path there is no
				// distro-not-vulnerable ignore either -- the matcher is a complete no-op.
				version := "0:2.34-60.el9_2.14"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", eus92, version, pkg.ID("glibc-eus-"+version))
				db.Match(t, &matcher, p).IsEmpty()
			})

			t.Run("9.2+eus host below its stream fix", func(t *testing.T) {
				// a genuinely vulnerable EUS host must still match, carry its own minor's
				// fix (reachable: fix minor 2 <= host minor 2), and name that stream's
				// RHSA -- not the GA build.
				version := "0:2.34-60.el9_2.1"
				matcher := Matcher{}
				p := rhelStreamHost("glibc", eus92, version, pkg.ID("glibc-eus-"+version))
				sf := db.Match(t, &matcher, p).
					SelectMatch("CVE-2023-4813").
					HasFix(vulnerability.FixStateFixed, "0:2.34-60.el9_2.7").
					WithAdvisoryLink("RHSA-2023:5453", "https://access.redhat.com/errata/RHSA-2023:5453")
				// the EUS merge fuses one detail per lookup: the channel-less disclosure
				// fetch and the +eus resolution fetch, both against the 9.2 row's constraint.
				const streamConstraint = "< 0:2.34-60.el9_2.7 (rpm)"
				sf.SelectDetailByDistro("redhat", "9.2", streamConstraint).HasMatchType(match.ExactDirectMatch)
				sf.SelectDetailByDistro("redhat", "9.2+eus", streamConstraint).HasMatchType(match.ExactDirectMatch)
			})
		})
}

// TestRpmPerMinorExpansion_NtpGARebase exercises the real GA-rebase inference (CVE-2015-7979,
// ntp): a pinned 7.2 fix (RHSA-2016:1141, 0:4.2.6p5-22.el7_2.2) plus a GA build
// (RHSA-2016:2583, 0:4.2.6p5-25.el7, Minor=null) whose EVR outranks the pinned fix. The
// transformer infers the GA at minor 3, closing the false negative for a 7.3 host below the
// GA build, while minor-2 governance (and its advisory) is unchanged.
func TestRpmPerMinorExpansion_NtpGARebase(t *testing.T) {
	const (
		linkGA = "https://access.redhat.com/errata/RHSA-2016:2583"
		link72 = "https://access.redhat.com/errata/RHSA-2016:1141"
		fixGA  = "0:4.2.6p5-25.el7"
		fix72  = "0:4.2.6p5-22.el7_2.2"
	)
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2015-7979").
		Run(func(t *testing.T, db *dbtest.DB) {
			t.Run("7.2 host at its stream fix", func(t *testing.T) {
				p := rhelStreamHost("ntp", distro.New(distro.RedHat, "7.2", ""), fix72, pkg.ID("ntp-7.2-fix"))
				db.Match(t, &Matcher{}, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2015-7979")
			})

			t.Run("7.2 host below its stream fix", func(t *testing.T) {
				v := "0:4.2.6p5-22.el7_2.1"
				p := rhelStreamHost("ntp", distro.New(distro.RedHat, "7.2", ""), v, pkg.ID("ntp-"+v))
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2015-7979").
					HasFix(vulnerability.FixStateFixed, fix72).
					WithAdvisoryLink("RHSA-2016:1141", link72).
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			t.Run("7.3 host below the inferred GA fix", func(t *testing.T) {
				// the closed FN: minor 3 above the highest pinned (7.2), below the GA build.
				// Without inference the GA is dropped and this host is cleared; with it the
				// inferred minor-3 row (< 0:4.2.6p5-25.el7) flags it, carrying the GA errata.
				v := "0:4.2.6p5-24.el7"
				p := rhelStreamHost("ntp", distro.New(distro.RedHat, "7.3", ""), v, pkg.ID("ntp-"+v))
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2015-7979").
					HasFix(vulnerability.FixStateFixed, fixGA).
					WithAdvisoryLink("RHSA-2016:2583", linkGA).
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			t.Run("7.3 host at the inferred GA fix", func(t *testing.T) {
				p := rhelStreamHost("ntp", distro.New(distro.RedHat, "7.3", ""), fixGA, pkg.ID("ntp-7.3-fix"))
				db.Match(t, &Matcher{}, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2015-7979")
			})
		})
}

// TestRpmPerMinorExpansion_KernelGASuperseded proves the safe-drop path with a real record
// (CVE-2018-3639, el6 kernel): pinned fixes on 6.9 (RHSA-2018:1651, 0:2.6.32-696.30.1.el6)
// and 6.10 (RHSA-2018:2164, 0:2.6.32-754.2.1.el6) plus a GA build (RHSA-2018:1854,
// 0:2.6.32-754.el6, Minor=null) whose EVR is BELOW the 6.10 z-stream fix. The GA is superseded
// and dropped (the pinned fix already covers it), so it becomes nobody's fix - a 6.10 host
// sitting exactly at the GA build is still flagged, judged against the real 6.10 z-stream
// fix and its advisory. Minor governance is otherwise unchanged.
func TestRpmPerMinorExpansion_KernelGASuperseded(t *testing.T) {
	const (
		fix9   = "0:2.6.32-696.30.1.el6"
		fix10  = "0:2.6.32-754.2.1.el6"
		gaBld  = "0:2.6.32-754.el6"
		link9  = "https://access.redhat.com/errata/RHSA-2018:1651"
		link10 = "https://access.redhat.com/errata/RHSA-2018:2164"
	)
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2018-3639").
		Run(func(t *testing.T, db *dbtest.DB) {
			t.Run("6.10 host at its own z-stream fix", func(t *testing.T) {
				p := rhelStreamHost("kernel", distro.New(distro.RedHat, "6.10", ""), fix10, pkg.ID("kernel-6.10-fix"))
				db.Match(t, &Matcher{}, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-3639")
			})

			t.Run("6.10 host at the dropped GA build is still flagged", func(t *testing.T) {
				// the GA build was superseded, so it is not a fix; the 6.10 host is judged
				// against the real 6.10 z-stream fix (< 0:2.6.32-754.2.1.el6) and 754.el6
				// sorts below it.
				p := rhelStreamHost("kernel", distro.New(distro.RedHat, "6.10", ""), gaBld, pkg.ID("kernel-6.10-ga"))
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2018-3639").
					HasFix(vulnerability.FixStateFixed, fix10).
					WithAdvisoryLink("RHSA-2018:2164", link10).
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			t.Run("6.9 host at its own fix", func(t *testing.T) {
				p := rhelStreamHost("kernel", distro.New(distro.RedHat, "6.9", ""), fix9, pkg.ID("kernel-6.9-fix"))
				db.Match(t, &Matcher{}, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-3639")
			})

			t.Run("6.9 host below its own fix", func(t *testing.T) {
				v := "0:2.6.32-696.el6"
				p := rhelStreamHost("kernel", distro.New(distro.RedHat, "6.9", ""), v, pkg.ID("kernel-"+v))
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2018-3639").
					HasFix(vulnerability.FixStateFixed, fix9).
					WithAdvisoryLink("RHSA-2018:1651", link9).
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})
		})
}
