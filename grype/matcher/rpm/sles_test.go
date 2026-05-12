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

// CVE-2024-49766 (the python311-Werkzeug NAK from issue #2566) on sles:15.6:
// vunnel emits FixedIn Version="0", v6 stores it as an UnaffectedPackageHandle,
// and the matcher converts it to a "Distro Not Vulnerable" ignore. SLES
// counterpart to TestMatcherRpm_UnaffectedRecordProducesIgnore (rhel:8/glibc).
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

// One Match() call on python311-Werkzeug at 2.3.0 on sles:15.6 must produce
// both a CVE-2023-25577 match (below SUSE fix 2.3.6) and a CVE-2024-49766 NAK
// ignore. SLES counterpart to TestMatcherRpm_VulnerableAndUnaffectedInSameCall;
// proves standardMatches splits disclosure and unaffected paths on non-rhel.
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

// A sles:15.6 NAK must not leak onto a sles:15.7 scan when both minors have
// OS rows: the exact-version lookup hits 15.7 directly and skips the loose
// any-minor fallback. The 15.7 fixture entry (glibc/CVE-2024-2961, unrelated)
// makes the row exist - drop it and the 15.6 NAK leaks back.
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

// Pairs with RecordsDoNotCrossMinorVersion: asserts the sles:15.7 fixture
// entry is wired up. Without this guard, dropping the 15.7 entry would make
// RecordsDoNotCrossMinorVersion trivially pass (no OS row → nothing matches)
// for the wrong reason. glibc 2.36 < SUSE 15.7 fix 2.38 → vulnerable.
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

// sles:15 means SLES 15 GA / SP0, not "all of SLES 15.x" - the OVAL feed
// lists it alongside SP1..SP6 as a distinct platform (cpe:/o:suse:sles:15).
// A GA host reports VERSION_ID="15" → MinorVersion="" → exact-match on the
// sles:15 row, no fallback. python3-Werkzeug only - confirms the GA path.
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

// Latent leak, not desired: a scan of an unknown SLES minor (15.99) inherits
// sles:15 GA NAKs via the major+empty-minor fallback. Harmless today (15.1-
// 15.7 each have rows) but the day searchForOSExactVersions learns SLES
// publishes per-minor, swap this assertion for IsEmpty().
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
