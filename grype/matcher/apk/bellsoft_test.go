package apk

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherApk_BellSoft drives BellSoft apk matching against a DB built from
// a real BellSoft OSV record (BELL-CVE-2025-59375 / expat). BellSoft records
// are distro-keyed affected ranges (like alpine secdb, not application
// ecosystems), so the apk matcher finds them via its distro search — the
// transformer derives an OperatingSystem from each OSV ecosystem string.
//
// BELL-CVE-2025-59375 fixes expat 2.7.2-r0 across three release lines each with
// its own affected floor:
//
//	Alpaquita / BellSoft Hardened Containers : stream  → [2.4.9-r0, 2.7.2-r0)
//	Alpaquita / BellSoft Hardened Containers : 23      → [2.5.0-r0, 2.7.2-r0)
//	Alpaquita / BellSoft Hardened Containers : 25      → [2.7.1-r0, 2.7.2-r0)
func TestMatcherApk_BellSoft(t *testing.T) {
	dbtest.DBs(t, "bellsoft-alpaquita").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		alpaquitaStream := distro.New(distro.Alpaquita, "stream", "")
		alpaquita23 := distro.New(distro.Alpaquita, "23", "")
		alpaquita25 := distro.New(distro.Alpaquita, "25", "")
		bhcStream := distro.New(distro.BellSoftHardenedContainers, "stream", "")

		// vulnerable expat on rolling Alpaquita (stream floor 2.4.9-r0).
		t.Run("alpaquita stream: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(alpaquitaStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// same version, numbered release 23 (floor 2.5.0-r0): still vulnerable.
		t.Run("alpaquita 23: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(alpaquita23).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// same version, release 25 has a higher floor (2.7.1-r0), so 2.6.0-r0 is
		// outside the affected range: no vulnerability match. Proves per-release
		// version scoping via the OS derived from the ecosystem string. The apk
		// matcher still emits DistroPackageFixed ignores (record ID + upstream
		// CVE) so a distro-not-affected verdict can suppress an NVD/CPE dupe.
		t.Run("alpaquita 25: version outside the release range does not match", func(t *testing.T) {
			pkgID := pkg.ID("expat-alpaquita25-below-floor")
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(alpaquita25).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2025-59375", "CVE-2025-59375").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2025-59375", "CVE-2025-59375").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// release 25 at its floor (2.7.1-r0) is vulnerable.
		t.Run("alpaquita 25: at the release floor matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.7.1-r0", syftPkg.ApkPkg).
				WithDistro(alpaquita25).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// the fix (2.7.2-r0) is at/above every affected range: no vulnerability
		// match, and the DistroPackageFixed ignores fire for the record ID and
		// the upstream CVE.
		t.Run("alpaquita stream: fixed version does not match", func(t *testing.T) {
			pkgID := pkg.ID("expat-alpaquita-stream-fixed")
			p := dbtest.NewPackage("expat", "2.7.2-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(alpaquitaStream).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2025-59375", "CVE-2025-59375").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2025-59375", "CVE-2025-59375").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// real Alpaquita/BHC images ship the binary subpackage `libexpat` whose
		// apk origin is `expat`; the record keys `expat`, so the match resolves
		// through the origin-package indirection.
		t.Run("alpaquita stream: libexpat matches via origin package expat", func(t *testing.T) {
			p := dbtest.NewPackage("libexpat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(alpaquitaStream).
				WithUpstream("expat", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})

		// the same record covers BellSoft Hardened Containers, a distinct distro
		// carried in the same OSV record's ecosystems.
		t.Run("bellsoft hardened containers stream: vulnerable expat matches", func(t *testing.T) {
			p := dbtest.NewPackage("expat", "2.6.0-r0", syftPkg.ApkPkg).
				WithDistro(bhcStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2025-59375").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
	})
}

// TestMatcherApk_BellSoft_SBOMImages drives matching with package name/version/
// origin tuples taken verbatim from real BellSoft image SBOMs (see ./sboms in
// the datasources workspace) against records extracted from a real vunnel run.
//
// The records show BellSoft's per-release binary lines diverging for the same
// CVE, which is what these cases exercise:
//
//	BELL-CVE-2026-34180 (openssl): 23 → [3.0.8-r4, 3.0.21-r0), 25 → [3.5.0-r0, 3.5.7-r0), stream → [3.1.1-r1, 3.5.7-r0)
//	BELL-CVE-2026-21637 (nodejs):  23 → fixed 20.20.0-r0, 25 → fixed 22.22.2-r0, stream → fixed 24.14.1-r0
//	BELL-CVE-2026-3219  (py3-pip): stream only → [22.3.1-r2, 26.1-r0)
func TestMatcherApk_BellSoft_SBOMImages(t *testing.T) {
	dbtest.DBs(t, "bellsoft-alpaquita").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		alpaquitaStream := distro.New(distro.Alpaquita, "stream", "")
		alpaquita25 := distro.New(distro.Alpaquita, "25", "")
		bhcStream := distro.New(distro.BellSoftHardenedContainers, "stream", "")

		// bellsoft-alpaquita-base-latest: libcrypto3 3.5.6-r0 (origin openssl) is
		// one release behind the stream fix 3.5.7-r0.
		t.Run("alpaquita base image: libcrypto3 matches openssl record via origin", func(t *testing.T) {
			p := dbtest.NewPackage("libcrypto3", "3.5.6-r0", syftPkg.ApkPkg).
				WithDistro(alpaquitaStream).
				WithUpstream("openssl", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-34180").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})

		// bellsoft-alpaquita-nodejs (current image): libssl3 3.5.7-r0 sits exactly
		// at the stream fix boundary — patched, so no match, and the matcher emits
		// DistroPackageFixed ignores for the record ID and upstream CVE.
		t.Run("alpaquita nodejs image: libssl3 at the fix boundary does not match", func(t *testing.T) {
			pkgID := pkg.ID("libssl3-at-fix-boundary")
			p := dbtest.NewPackage("libssl3", "3.5.7-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(alpaquitaStream).
				WithUpstream("openssl", "").
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-34180", "CVE-2026-34180").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-34180", "CVE-2026-34180").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// bellsoft-nodejs-24-glibc (older image): nodejs 24.14.0-r0 is below the
		// stream fix 24.14.1-r0.
		t.Run("nodejs 24 image: vulnerable nodejs matches", func(t *testing.T) {
			p := dbtest.NewPackage("nodejs", "24.14.0-r0", syftPkg.ApkPkg).
				WithDistro(alpaquitaStream).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-21637").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// the same nodejs 24.14.0-r0 on release 25: that release tracks the 22.x
		// line (fixed 22.22.2-r0), so 24.14.0-r0 is beyond its affected window —
		// the per-release OS scoping keeps the stream range from bleeding over.
		t.Run("nodejs 24 on alpaquita 25: different release line does not match", func(t *testing.T) {
			pkgID := pkg.ID("nodejs-alpaquita25-different-line")
			p := dbtest.NewPackage("nodejs", "24.14.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(alpaquita25).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-21637", "CVE-2026-21637").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-21637", "CVE-2026-21637").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// bellsoft-hardened-python-glibc (current image): py3-pip 26.1.2-r0 is
		// above the fix 26.1-r0 — the hardened image ships patched packages.
		t.Run("bhc python image: patched py3-pip does not match", func(t *testing.T) {
			pkgID := pkg.ID("py3-pip-bhc-patched")
			p := dbtest.NewPackage("py3-pip", "26.1.2-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(bhcStream).
				Build()

			db.Match(t, &matcher, p).
				DoesNotHaveAnyVulnerabilities("BELL-CVE-2026-3219", "CVE-2026-3219").
				Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed", "BELL-CVE-2026-3219", "CVE-2026-3219").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// same image's py3-pip-pyc subpackage at a realistic earlier version
		// (25.2-r0, inside [22.3.1-r2, 26.1-r0)) resolves through its origin
		// py3-pip on BHC.
		t.Run("bhc: earlier py3-pip-pyc matches via origin py3-pip", func(t *testing.T) {
			p := dbtest.NewPackage("py3-pip-pyc", "25.2-r0", syftPkg.ApkPkg).
				WithDistro(bhcStream).
				WithUpstream("py3-pip", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("BELL-CVE-2026-3219").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
	})
}
