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
