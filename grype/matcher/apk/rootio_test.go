package apk

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherApk_RootIO drives rootio apk matching against a DB that mixes
// rootio NAK records, NVD CPE-keyed disclosures, and an alpine secdb fix
// record. The fixture covers four rootio-fixed CVEs on alpine 3.18 —
// libuv, nghttp2, wget, socat — three of which also have NVD CPE entries,
// plus the existing alpine318 fixture's CVE-2024-0727 for the standard
// secdb path.
//
// Alpine's secdb is sparse: the alpine project tracks a narrow set of
// CVEs. Real-world rootio scans therefore rely on NVD CPE matching for
// most disclosures. The apk matcher surfaces:
//
//   - the NVD CPE match in its `matches` output (downstream pipeline
//     then drops it when the matcher also emits a covering IgnoreFilter);
//   - the rootio NAK as DistroPackageFixed IgnoreFilters that
//     alias-unwind into the rootio record ID + the upstream CVE.
//
// The tests assert both signals: the raw match coming out of the
// matcher, and the alias-unwound ignore filters that downstream code
// uses to suppress it. Cases without a disclosure to suppress (socat,
// which has no NVD CPE entry) still emit the NAK ignore — the matcher
// reports NAKs from the unaffected set whether or not a disclosure
// exists in the same scan.
//
// CVE coverage:
//
//	CVE-2024-24806 / libuv:    rootio + nvd     (rootio fix 1.44.2-r20071, nvd vEnd 1.48.0)
//	CVE-2024-28182 / nghttp2:  rootio + nvd     (rootio fix 1.57.0-r00072, nvd vEnd 1.61.0)
//	CVE-2024-10524 / wget:     rootio + nvd     (rootio fix 1.21.4-r00071, nvd vEnd 1.25.0)
//	CVE-2024-54661 / socat:    rootio only      (rootio fix 1.7.4.4-r10071)
//	CVE-2024-0727  / openssl:  nvd + alpine     (alpine fix 3.1.4-r5)
func TestMatcherApk_RootIO(t *testing.T) {
	dbtest.DBs(t, "rootio-alpine-318").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		// rootio-libuv at the rootio fix. NVD CPE flags 1.44.2 (< vEnd
		// 1.48.0) — match surfaces. The rootio NAK matches alias
		// CVE-2024-24806 and appears as the DistroPackageFixed ignore
		// pair that downstream code uses to drop the match.
		t.Run("rootio-libuv at rootio fix: CPE match + NAK ignore", func(t *testing.T) {
			pkgID := pkg.ID("rootio-libuv-at-fix")
			p := dbtest.NewPackage("rootio-libuv", "1.44.2-r20071", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:libuv:libuv:1.44.2:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2024-24806").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
			findings.Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed",
					"ROOT-OS-ALPINE-318-CVE-2024-24806",
					"CVE-2024-24806").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// rootio-libuv below the rootio fix. NVD CPE matches (1.40.0 <
		// 1.48.0). The rootio NAK requires >= 1.44.2-r20071 so it
		// doesn't apply — the match stands alone, no ignore.
		t.Run("rootio-libuv below rootio fix: NVD CPE flags it, no NAK", func(t *testing.T) {
			p := dbtest.NewPackage("rootio-libuv", "1.40.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:libuv:libuv:1.40.0:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-24806").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})

		// rootio-nghttp2 at rootio fix: same shape as libuv, different
		// package and CVE.
		t.Run("rootio-nghttp2 at rootio fix: CPE match + NAK ignore", func(t *testing.T) {
			pkgID := pkg.ID("rootio-nghttp2-at-fix")
			p := dbtest.NewPackage("rootio-nghttp2", "1.57.0-r00072", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:nghttp2:nghttp2:1.57.0:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2024-28182").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
			findings.Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed",
					"ROOT-OS-ALPINE-318-CVE-2024-28182",
					"CVE-2024-28182").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// rootio-wget below rootio fix.
		t.Run("rootio-wget below rootio fix: NVD CPE flags it", func(t *testing.T) {
			p := dbtest.NewPackage("rootio-wget", "1.21.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:gnu:wget:1.21.0:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-10524").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})

		// rootio-wget at rootio fix.
		t.Run("rootio-wget at rootio fix: CPE match + NAK ignore", func(t *testing.T) {
			pkgID := pkg.ID("rootio-wget-at-fix")
			p := dbtest.NewPackage("rootio-wget", "1.21.4-r00071", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:gnu:wget:1.21.4:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2024-10524").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
			findings.Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed",
					"ROOT-OS-ALPINE-318-CVE-2024-10524",
					"CVE-2024-10524").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// rootio-socat at rootio fix. CVE-2024-54661 has no NVD CPE entry
		// so there's no disclosure to suppress — but the matcher still
		// emits the NAK as a DistroPackageFixed ignore (it lives in
		// `fixed` after fixed.Merge(unaffected)). This is the
		// "rootio-only" combination.
		t.Run("rootio-socat at rootio fix: NAK ignore only, no disclosure", func(t *testing.T) {
			pkgID := pkg.ID("rootio-socat-at-fix")
			p := dbtest.NewPackage("rootio-socat", "1.7.4.4-r10071", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed",
					"ROOT-OS-ALPINE-318-CVE-2024-54661",
					"CVE-2024-54661").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})

		// Regular openssl below the alpine secdb fix. Alpine secdb says
		// CVE-2024-0727 is fixed at 3.1.4-r5; 3.1.0-r0 sits below. The
		// matcher reports it via direct secdb match. The rootio NAK
		// keyed under rootio-prefixed names never reaches a regular
		// `openssl` scan.
		t.Run("regular openssl below alpine fix: secdb direct match", func(t *testing.T) {
			p := dbtest.NewPackage("openssl", "3.1.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		// Regular openssl at alpine fix: distro-fixed, no rootio.
		t.Run("regular openssl at alpine fix: distro-fixed", func(t *testing.T) {
			pkgID := pkg.ID("openssl-at-alpine-fix")
			p := dbtest.NewPackage("openssl", "3.1.4-r5", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore("DistroPackageFixed", "CVE-2024-0727").
				ForPackage(pkgID)
		})

		// Unrelated package: no cross-contamination.
		t.Run("unrelated package: nothing", func(t *testing.T) {
			p := dbtest.NewPackage("musl", "1.2.4-r2", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
	})
}
