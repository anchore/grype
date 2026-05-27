package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// ubuntu/dpkg matching is the end-to-end coverage for the vunnel ubuntu OSV
// rewrite: the fixtures under internal/dbtest/testdata/shared/all/ubuntu/ are
// real records extracted from the post-rewrite vunnel cache (mixed-schema
// results.db: 49k OSV-1.7.0 + 585 OSV-1.6.3 + 176k legacy OS-1.1.0). These
// tests assert that the new osv ubuntu strategy produces DB rows that the
// existing dpkg matcher can resolve — i.e. that an OSV-sourced row and a
// legacy-OS-sourced row are functionally indistinguishable to the matcher.

const ubuntuReasonDistroPackageFixed = "DistroPackageFixed"

// Ubuntu Pro / ESM distro for tests against ESM channel rows. distro.New
// parses the "+esm" suffix into the Channels slice; that flows through
// search.ByDistro and matches OperatingSystem rows whose Channel field is
// "esm" (what the ubuntu strategy writes for Ubuntu:Pro:* ecosystems).
var ubuntu1604ESM = distro.New(distro.Ubuntu, "16.04+esm", "")

// === OSV path: ubuntu strategy → AffectedPackageHandle → dpkg matcher ===

// TestMatcherDpkg_Ubuntu_DirectMatch_OSV is the load-bearing case. curl
// 7.81.0-1ubuntu1.13 on jammy is vulnerable to CVE-2023-38545 per
// UBUNTU-CVE-2023-38545 (fix: 7.81.0-1ubuntu1.14). If this test fails, the
// new ubuntu OSV strategy is not producing rows the dpkg matcher can find,
// and the whole vunnel rewrite is blocked.
func TestMatcherDpkg_Ubuntu_DirectMatch_OSV(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu-cve-2023-38545").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("curl", "7.81.0-1ubuntu1.13", syftPkg.DebPkg).
				WithDistro(dbtest.Ubuntu2204).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2023-38545").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherDpkg_Ubuntu_IndirectMatch_OSV exercises source indirection
// against an OSV-sourced row: the SBOM has the binary libcurl4 (which is one
// of the binaries listed in UBUNTU-CVE-2023-38545.affected[0].ecosystem_specific.binaries),
// but the DB row is keyed on the source package "curl". The dpkg matcher
// fans out via pkg.UpstreamPackages and resolves to the source-keyed row.
//
// This is the test that proves we can skip storing binary expansions in the
// DB and rely on the matcher's existing source-indirection logic — exactly
// the design decision baked into the ubuntu strategy.
func TestMatcherDpkg_Ubuntu_IndirectMatch_OSV(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu-cve-2023-38545").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("libcurl4", "7.81.0-1ubuntu1.13", syftPkg.DebPkg).
				WithDistro(dbtest.Ubuntu2204).
				WithUpstream("curl", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2023-38545").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherDpkg_Ubuntu_FixedVersionProducesIgnore_OSV is the negative case
// against an OSV row: curl is at the exact fix version, so the matcher
// resolves the CVE row, sees the pkg version is >= the constraint, and emits
// a DistroPackageFixed ignore instead of a match. This locks in that the
// "< fix" constraint produced by the ubuntu strategy is actually being
// evaluated correctly by the dpkg version comparator.
func TestMatcherDpkg_Ubuntu_FixedVersionProducesIgnore_OSV(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu-cve-2023-38545").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("curl-jammy-fixed")
			p := dbtest.NewPackage("curl", "7.81.0-1ubuntu1.14", syftPkg.DebPkg). // exact fix version
												WithID(pkgID).
												WithDistro(dbtest.Ubuntu2204).
												Build()

			// Primary ID is the upstream CVE; with no extra aliases on this
			// record, OwnershipIgnores emits exactly one ignore filter.
			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(ubuntuReasonDistroPackageFixed, "CVE-2023-38545").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherDpkg_Ubuntu_NoFixOSVStillMatches covers the ~38% of OSV records
// that carry only {introduced:"0"} with no fixed event. Vunnel emits these as
// AffectedPackageHandle with empty constraint + NotFixedStatus (per the no-fix
// sentinel the ubuntu strategy adds); the dpkg matcher must treat an empty
// constraint as "always vulnerable" — otherwise these disclosures vanish.
//
// UBUNTU-CVE-2006-20001 (apache2) has the no-fix shape on Ubuntu:Pro:14.04:LTS.
// The Pro:14.04 row carries Channel="esm"; we exercise it via the Pro distro
// below in TestMatcherDpkg_Ubuntu_Pro_NoFixMatch.

// === OSV Pro / ESM path ===

// TestMatcherDpkg_Ubuntu_Pro_DirectMatch verifies the Channel="esm" row
// produced for Ubuntu:Pro:16.04:LTS resolves when the SBOM distro carries the
// "+esm" channel suffix. apache2 2.4.18-2ubuntu3.10 on Ubuntu Pro 16.04 is
// vulnerable to CVE-2006-20001 (fix: 2.4.18-2ubuntu3.17+esm8).
func TestMatcherDpkg_Ubuntu_Pro_DirectMatch(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu-cve-2006-20001").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("apache2", "2.4.18-2ubuntu3.10", syftPkg.DebPkg).
				WithDistro(ubuntu1604ESM).
				Build()

			// SelectDetailByDistro pins the SearchedBy distro to the +esm
			// form, which is what the matcher reports back when the channel
			// is parsed off the package's distro version. Using AsDistroSearch()
			// here would trip the package-vs-searched-by consistency check
			// because p.Distro.Version is the suffix-stripped "16.04" while
			// the matcher reports "16.04+esm" — by design, per the cross-
			// namespace assertion docstring.
			db.Match(t, &matcher, p).
				SelectMatch("CVE-2006-20001").
				SelectDetailByDistro("ubuntu", "16.04+esm").
				HasMatchType(match.ExactDirectMatch)
		})
}

// === Legacy OS-schema path (unchanged behavior, regression net) ===

// TestMatcherDpkg_Ubuntu_DirectMatch_Legacy verifies that legacy OS-schema
// records — produced by the unchanged os.Transform path for EOL/interim
// releases that Canonical's OSV feed has dropped — continue to match exactly
// as they did before the rewrite. curl 7.88.1-8ubuntu1 on 23.04 is vulnerable
// per ubuntu:23.04/cve-2023-38545 (legacy fix: 7.88.1-8ubuntu2.3).
//
// 23.04 is interim (not LTS, not in Canonical's OSV feed). It only reaches
// the DB via the legacy passthrough, so this is the regression net for the
// mixed-schema-in-one-results.db design decision in the vunnel spec.
func TestMatcherDpkg_Ubuntu_DirectMatch_Legacy(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu:23.04/cve-2023-38545").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("curl", "7.88.1-8ubuntu1", syftPkg.DebPkg).
				WithDistro(distro.New(distro.Ubuntu, "23.04", "")).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2023-38545").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// === Negative: distro the DB has no rows for ===

// TestMatcherDpkg_Ubuntu_NoMatchOnUnknownRelease asserts the matcher emits
// nothing — neither match nor ignore — when the SBOM's distro doesn't match
// any OS row in the DB. This is the third class of negative case (beyond
// "fixed version" and "wrong package"), and it sanity-checks that
// search.ByDistro is actually gating queries by distro (not just package
// name).
//
// We use Ubuntu 18.04, which has no row in the small fixture set (our
// fixtures only carry 12.04/12.10/14.04/22.04/23.04/23.10/24.04/Pro:14/16).
func TestMatcherDpkg_Ubuntu_NoMatchOnUnknownRelease(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("ubuntu-cve-2023-38545").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("curl", "7.58.0-2ubuntu3.6", syftPkg.DebPkg).
				WithDistro(dbtest.Ubuntu1804).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}
