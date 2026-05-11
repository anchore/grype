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

// TestMatcherRpm_SLES_NAKDoesNotCrossMinorVersion locks in the strict-by-default
// scoping for unaffected/NAK lookups. SUSE publishes per-minor-version OVAL
// feeds (sles:15.6, sles:15.7, ...). The NAK in sles:15.6 must NOT apply to a
// scan of a sles:15.7 package because SUSE may not have re-confirmed the
// not-affected status for SP7; silently extending the 15.6 NAK to a 15.7 scan
// would falsely suppress GHSA findings on the bundled language-ecosystem
// package.
//
// The disclosure-side fallback (sles:15.6 disclosure → applies to sles:15.7)
// is unaffected by this; only the unaffected/NAK path is strict. See
// applyUnaffectedOSStrictness in grype/db/v6/search_query.go.
func TestMatcherRpm_SLES_NAKDoesNotCrossMinorVersion(t *testing.T) {
	dbtest.DBs(t, "sles15").
		SelectOnly("sles:15.6/cve-2024-49766").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// same package as the NAK, but on sles:15.7 (the NAK lives in sles:15.6)
			p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.6-150700.6.12.1", syftPkg.RpmPkg).
				WithDistro(distro.New(distro.SLES, "15.7", "")).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestMatcherRpm_SLES_DisclosureDoesCrossMinorVersion is the regression guard
// for the other half of applyUnaffectedOSStrictness. The strict-NAK fix gates
// itself on unaffectedOnly and must NEVER leak onto disclosure queries - if
// it did, every cross-minor disclosure match for RHEL/SLES would silently
// drop, which would be a serious regression invisible to existing CI (the
// rest of the matcher tests put the package and the disclosure record on the
// same minor).
//
// Setup mirrors the NAK-doesn't-cross test above (sles:15.7 scan against a
// sles:15.6 record) but for the disclosure (CVE-2023-25577) instead of the
// NAK. python311-Werkzeug at 2.3.0 is below the 15.6 fix at 2.3.6, so the
// loose major-with-any-minor fallback must hit and emit a direct match. If
// this test ever fails, look for someone extending DisableCrossMinorFallback
// onto the non-unaffected code path.
func TestMatcherRpm_SLES_DisclosureDoesCrossMinorVersion(t *testing.T) {
	dbtest.DBs(t, "sles15").
		SelectOnly("sles:15.6/cve-2023-25577").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// 2.3.0 < SUSE 15.6 fix at 2.3.6 → vulnerable for CVE-2023-25577
			p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.0-150700.6.1.1", syftPkg.RpmPkg).
				WithDistro(dbtest.SLES157).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2023-25577").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherRpm_SLES_DisclosureCrossesButNAKDoesNot ties both halves of the
// asymmetric strict-NAK design together in one Match() call. With both the
// 15.6 disclosure (CVE-2023-25577, real fix at 2.3.6) and the 15.6 NAK
// (CVE-2024-49766, FixedIn Version="0") loaded, scanning a vulnerable
// python311-Werkzeug on sles:15.7 must produce:
//   - exactly one match for CVE-2023-25577 (disclosure crossed the minor)
//   - zero ignores (NAK strictness held; the 15.6 NAK didn't bleed onto 15.7)
//
// Together with TestMatcherRpm_SLES_NAKDoesNotCrossMinorVersion (NAK-side
// alone) and TestMatcherRpm_SLES_DisclosureDoesCrossMinorVersion (disclosure-
// side alone), this brackets the asymmetric behavior end-to-end. The
// matches-side and ignores-side completeness checks enforce no extras
// snuck in.
func TestMatcherRpm_SLES_DisclosureCrossesButNAKDoesNot(t *testing.T) {
	dbtest.DBs(t, "sles15").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("python311-Werkzeug", "0:2.3.0-150700.6.1.1", syftPkg.RpmPkg).
			WithDistro(dbtest.SLES157).
			Build()

		db.Match(t, &matcher, p).
			SelectMatch("CVE-2023-25577").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
	})
}
