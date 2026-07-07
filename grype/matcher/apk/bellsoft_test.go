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
