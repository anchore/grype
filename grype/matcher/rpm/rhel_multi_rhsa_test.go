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

// The fixture (testdata/rhel-multi-rhsa) holds hand-authored rhel:9 records in
// verbatim OS schema. dbtest runs the real grype-db transform over them, so these tests
// validate the whole vunnel -> grype-db -> grype matching path, not hand-built v6
// constraints. Three records live there:
//
//   - CVE-2024-8088 (python3.9): the multi-RHSA phase-1 record - two RHSAs fixing
//     distinct upstream bases (the 9.4 Z-stream backport 3.9.18-3.el9_4.5 and the 9.5 GA
//     rebase 3.9.19-8.el9) reduced to one record whose VulnerableRange partitions the
//     streams: < 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9
//   - CVE-2023-4813 (glibc) and CVE-9999-0001 (streamtest): per-minor `Advisories`
//     records that the v6 OS transformer expands into per-minor operating_system rows
//     (see TestRpmPerMinorExpansion_* below).
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

// Server-side stream-affinity (per-minor row expansion) tests.
//
// These prove that an UNMODIFIED (stock main) rpm.Matcher produces correct minor-affine
// matching, purely because the v6 OS transformer expanded each record's per-stream
// `Advisories` list into per-minor operating_system rows (each carrying the fix that
// governs that minor) plus a major-only fallback row. The matcher is never touched; the
// only moving parts are the OS unmarshal struct (which now reads vunnel's per-stream
// `Advisories`) and the OS transformer's per-minor expansion. The assertions run the
// real vunnel -> grype-db -> grype path via the dbtest harness over the whole fixture
// (no SelectOnly), so unrelated records co-resident in the DB don't perturb the result.

// rhelStreamHost builds a plain RHEL binary RPM whose name equals the source RPM the
// RHEL data is keyed on, so the matcher's direct path engages (no source indirection).
func rhelStreamHost(name string, d *distro.Distro, version string, id pkg.ID) pkg.Package {
	return dbtest.NewPackage(name, version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

// TestRpmPerMinorExpansion_AlphaBravo exercises the synthetic two-stream record
// (CVE-9999-0001): fixes at 9.2 ("Alpha", 0:1-2.el9_2) and 9.3 ("Bravo", 0:1-3.el9_3).
// The transformer materializes rows for the known minors plus a major-only fallback, so
// the stock matcher resolves each host minor to the governing fix.
func TestRpmPerMinorExpansion_AlphaBravo(t *testing.T) { //nolint:funlen // table-driven minor-affinity cases
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			cases := []struct {
				name       string
				minor      string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "9.2 host below Alpha",
					minor:      "9.2",
					version:    "0:1-1.el9_2",
					vulnerable: true,
					why:        "minor=2 row governed by < Alpha (0:1-2.el9_2); host is below it",
				},
				{
					name:       "9.2 host at Alpha",
					minor:      "9.2",
					version:    "0:1-2.el9_2",
					vulnerable: false,
					why:        "host carries the 9.2 fix exactly; not < Alpha",
				},
				{
					name:       "9.3 host between Alpha and Bravo",
					minor:      "9.3",
					version:    "0:1-2.el9_3",
					vulnerable: true,
					why:        "minor=3 row governed by < Bravo (0:1-3.el9_3); Alpha must NOT clear it",
				},
				{
					name:       "9.3 host at Bravo",
					minor:      "9.3",
					version:    "0:1-3.el9_3",
					vulnerable: false,
					why:        "host carries the 9.3 fix exactly; not < Bravo",
				},
				{
					name:       "9.5 host above max known minor",
					minor:      "9.5",
					version:    "0:1-2.el9_5",
					vulnerable: true,
					why:        "no minor=5 row; resolves via major-only fallback (< Bravo); 0:1-2 < Bravo",
				},
				{
					name:       "9.5 host above max known minor, past Bravo",
					minor:      "9.5",
					version:    "0:1-3.el9_5",
					vulnerable: false,
					why:        "major-only fallback is < Bravo; host EVR is >= Bravo's leading release",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					d := distro.New(distro.RedHat, c.minor, "")
					matcher := Matcher{}
					pkgID := pkg.ID("streamtest-" + c.minor + "-" + c.version)
					p := rhelStreamHost("streamtest", d, c.version, pkgID)
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-9999-0001").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-9999-0001")
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
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})
		})
}

// TestRpmPerMinorExpansion_WebkitRebase guards the "compare EVR not release-int"
// requirement (CVE-9999-0002): pinned 2.38.5-1.el9_2.3 (minor 2) + GA 2.40.5-1.el9 (null
// minor). Their release ints tie at 1, but the GA's higher VERSION makes its EVR greater,
// so it is inferred at minor 3 (NOT dropped as superseded). A minor-3+ host below the GA
// build must be flagged.
func TestRpmPerMinorExpansion_WebkitRebase(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel93 := distro.New(distro.RedHat, "9.3", "")
			version := "0:2.40.4-1.el9"
			matcher := Matcher{}
			p := rhelStreamHost("webkit2gtk3", rhel93, version, pkg.ID("webkit2gtk3-"+version))
			db.Match(t, &matcher, p).
				SelectMatch("CVE-9999-0002").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestRpmPerMinorExpansion_KernelSuperseded proves the safe-drop path (CVE-9999-0003):
// pinned 4.18.0-513.5.1.el8_9 (minor 9) + GA 4.18.0-193.el8 (null minor, LOWER EVR). The
// GA is superseded by the pinnable fix -> dropped, materialized nowhere. A minor-9 host at
// or above the pinned fix is clean; nothing is flagged against the low GA build.
func TestRpmPerMinorExpansion_KernelSuperseded(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel89 := distro.New(distro.RedHat, "8.9", "")
			version := "0:4.18.0-513.5.1.el8_9"
			matcher := Matcher{}
			p := rhelStreamHost("kernel", rhel89, version, pkg.ID("kernel-"+version))
			db.Match(t, &matcher, p).
				Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-9999-0003")
		})
}
