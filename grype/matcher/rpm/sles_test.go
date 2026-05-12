package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherRpm_SLES_UnaffectedRecordProducesIgnore exercises the explicit-
// Unaffected arm of the standard rpm matcher for SUSE OVAL "is not affected"
// records: vunnel emits these as FixedIn entries with Version="0", which the
// v6 OS transformer turns into UnaffectedPackageHandle rows. The matcher's
// search.ForUnaffected() branch picks them up and emits a "Distro Not
// Vulnerable" IgnoreRelatedPackage filter so consumers can suppress related-
// package matches (the canonical case: a GHSA on the bundled PyPI Werkzeug
// that overlaps python311-Werkzeug by file ownership).
//
// This is the SLES counterpart to TestMatcherRpm_UnaffectedRecordProducesIgnore
// (rhel:8/glibc/CVE-1999-0199). CVE-2024-49766 is the exact CVE from issue
// #2566; SUSE marks both python3-Werkzeug and python311-Werkzeug as not
// affected on SLES 15.6 in the OVAL feed.
func TestMatcherRpm_SLES_UnaffectedRecordProducesIgnore(t *testing.T) {
	dbtest.DBs(t, "sles15").
		SelectOnly("sles:15.6/cve-2024-49766").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("python311-Werkzeug-unaffected")
			// the user's reported version from issue #2566
			p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.6-150400.6.12.1", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.SLES156).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-49766").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_SLES_VulnerableAndUnaffectedInSameCall verifies that the
// standard matcher correctly disentangles disclosure-side and unaffected-side
// results for the same package on SLES, in a single Match() call.
// CVE-2023-25577 has a real SUSE fix at 0:2.3.6-150400.6.6.1 - a package at
// 0:2.3.0 is below the fix and matches. CVE-2024-49766 is the NAK (FixedIn
// Version="0" → UnaffectedPackageHandle), which produces a "Distro Not
// Vulnerable" ignore. Both records are on python311-Werkzeug in sles:15.6,
// so the matcher must produce one match AND one ignore from the same query.
//
// This is the SLES counterpart to TestMatcherRpm_VulnerableAndUnaffectedInSameCall
// (rhel:8/glibc/CVE-2016-10228 + CVE-1999-0199); proves the two-path split in
// matcher.go's standardMatches works on a non-rhel namespace.
func TestMatcherRpm_SLES_VulnerableAndUnaffectedInSameCall(t *testing.T) {
	dbtest.DBs(t, "sles15").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		pkgID := pkg.ID("python311-Werkzeug-mixed")
		// 2.3.0 is below the SUSE fix at 2.3.6 → vulnerable for CVE-2023-25577
		p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.0-150400.6.1.1", syftPkg.RpmPkg).
			WithID(pkgID).
			WithDistro(dbtest.SLES156).
			Build()

		findings := db.Match(t, &matcher, p)
		findings.SelectMatch("CVE-2023-25577").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
		findings.Ignores().
			SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-49766").
			ForPackage(pkgID).
			WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
	})
}

// TestMatcherRpm_SLES_RecordsDoNotCrossMinorVersion is the cross-minor scoping
// guard for SLES. SUSE publishes per-minor-version OVAL feeds (sles:15.6,
// sles:15.7, ...) and the v6 transformer creates a distinct operating_system
// row for each. When the OS table contains a row for the scanned minor, the
// exact-version branch in operating_system_store.searchForOSExactVersions
// finds it and returns immediately - the loose "any minor with this major"
// fallback never fires, so records published against sibling minors stay put.
//
// What this protects against: the loose fallback only fires when no OS row
// matches the scanned version (exact, then empty-minor major). In a sparse
// test fixture where only sles:15.6 is loaded, that fallback returns the
// 15.6 row for a 15.7 query and any record on it (NAK or disclosure) leaks
// onto the 15.7 scan. The fixture for this test loads a sles:15.7 record
// (glibc/CVE-2024-2961, unrelated to python311-Werkzeug) precisely so the
// 15.7 OS row exists - mirroring production where every supported minor has
// its own feed - and asserting the leak does NOT happen. Drop the 15.7
// fixture entry from sles15/db.yaml and this test fails, demonstrating the
// hidden dependency.
//
// CVE-2024-49766 (the NAK from issue #2566) is published on sles:15.6 only;
// scanning python311-Werkzeug on sles:15.7 must produce no match and no
// ignore - the OS-row lookup hits sles:15.7 cleanly, finds no
// python311-Werkzeug records there, and the 15.6 NAK is never consulted.
func TestMatcherRpm_SLES_RecordsDoNotCrossMinorVersion(t *testing.T) {
	dbtest.DBs(t, "sles15").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// same package as the 15.6 NAK and 15.6 disclosure, but scanned
			// on 15.7; with the sles:15.7 fixture entry present, the OS-row
			// lookup hits 15.7 directly and neither 15.6 record leaks.
			p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.0-150700.6.1.1", syftPkg.RpmPkg).
				WithDistro(distro.New(distro.SLES, "15.7", "")).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestMatcherRpm_SLES_FixturePresenceOfMinorVersionRow verifies the test
// setup itself: scanning glibc on sles:15.7 must find CVE-2024-2961, which
// proves the sles:15.7 fixture entry is wired up and the OS table really
// does contain a sles:15.7 row. Without this guard, a future fixture edit
// could silently strip the 15.7 entry and TestMatcherRpm_SLES_RecordsDoNot
// CrossMinorVersion above would still pass (it asserts emptiness, so it's
// trivially true if nothing matches) - except the reason would be wrong:
// no OS row at all rather than the cross-minor block we mean to lock in.
//
// glibc 2.36 is below the SUSE 15.7 fix at 2.38 -> vulnerable.
func TestMatcherRpm_SLES_FixturePresenceOfMinorVersionRow(t *testing.T) {
	dbtest.DBs(t, "sles15").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("glibc", "0:2.36-150600.10.1.1", syftPkg.RpmPkg).
				WithDistro(dbtest.SLES157).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-2961").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherRpm_SLES_GANamespaceAppliesToGAScan locks in that sles:15
// records - vunnel namespaces with a blank minor - represent SLES 15 GA /
// SP0 specifically, NOT "all of SLES 15.x". Evidence from the OVAL source
// XML for CVE-2024-49766: <affected><platform> enumerates "SUSE Linux
// Enterprise Server 15" alongside SP1, SP2, ..., SP6 as distinct entries,
// and the corresponding CPE is cpe:/o:suse:sles:15 (no SP suffix). A host
// actually running SLES 15 GA reports VERSION_ID="15" in /etc/os-release;
// grype turns that into an OSSpecifier with MajorVersion="15" and
// MinorVersion="", which lands directly in the "empty minor version -
// exact match for major-only distros" branch of
// operating_system_store.searchForOSExactVersions and returns the sles:15
// OS row without falling back.
//
// The sles:15 record for CVE-2024-49766 carries only python3-Werkzeug as
// a NAK (sles:15.6 separately adds python311-Werkzeug, which postdates
// the GA stream - Python 3.11 wasn't in SLES 15 until later SPs). So
// asserting the NAK fires here proves the lookup hit the sles:15 row
// specifically, not the sles:15.6 row which also has python3-Werkzeug.
func TestMatcherRpm_SLES_GANamespaceAppliesToGAScan(t *testing.T) {
	dbtest.DBs(t, "sles15").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("python3-werkzeug-on-sles-15-ga")
			// SLES 15 GA host: VERSION_ID="15" -> distro major=15, minor=""
			p := dbtest.NewPackage("python3-Werkzeug", "0:0.16.1-150100.4.6.1", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(distro.New(distro.SLES, "15", "")).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-49766").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_SLES_GANamespaceLeaksOntoUnknownMinor documents a latent
// quirk in operating_system_store.searchForOSExactVersions, NOT a desired
// behavior. The fallback chain has a "major version with empty minor"
// step (between exact match and the loose any-minor fallback) that is
// commented as the "publisher chose major-only granularity" case - true
// for RHEL OVAL, false for SLES, where a blank-minor record is
// specifically the GA release. When grype scans a SLES minor that has
// no OS row in the DB (e.g. a notional 15.99 that hasn't been ingested
// yet), step 1 returns empty and the fallback silently returns the
// sles:15 GA row, applying its NAKs to the scan.
//
// This isn't currently a problem for users on any supported SLES minor
// (15.1-15.7) because each has its own OS row and step 1 always matches.
// But for a future SP that ships before grype's DB catches up, every
// sles:15 NAK would falsely suppress real findings on the new SP. The
// test is here so that the day someone teaches searchForOSExactVersions
// the SLES per-minor publishing model (e.g. only allow the major-only
// fallback when the publisher is known to use major-only granularity),
// this assertion flips - the right replacement at that point is
// IsEmpty() and a comment update explaining the fix.
//
// 15.99 was chosen as a clearly-notional minor that no SUSE feed will
// ever publish, so this test won't quietly start passing for the wrong
// reason if the fixture later gains a real high-numbered SP.
func TestMatcherRpm_SLES_GANamespaceLeaksOntoUnknownMinor(t *testing.T) {
	dbtest.DBs(t, "sles15").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("python3-werkzeug-on-unknown-sles-minor")
			p := dbtest.NewPackage("python3-Werkzeug", "0:0.16.1-150100.4.6.1", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(distro.New(distro.SLES, "15.99", "")).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-49766").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}
