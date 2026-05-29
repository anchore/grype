package apk

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// reasonDistroPackageFixed is the IgnoreRelatedPackage reason emitted by the
// shared internal/MatchPackageByDistro path for vulns the secdb considers
// fixed (or unaffected/NAK) for the package.
const reasonDistroPackageFixed = "DistroPackageFixed"

// reasonExplicitApkNak is the IgnoreRelatedPackage reason emitted by the
// apk-specific findNaksForPackage path for secdb entries with the apk
// "< 0" sentinel constraint.
const reasonExplicitApkNak = "Explicit APK NAK"

// reasonCPENotVulnerable is the IgnoreRelatedPackage reason emitted by
// MatchPackageByCPEs for CPE matches that resolved a vulnerability record
// for the package's CPE but whose version constraint is not satisfied by
// the package version (i.e., NVD says "not vulnerable at this version").
const reasonCPENotVulnerable = "CPE not vulnerable"

// === direct match (secdb) ===

func TestMatcherApk_DirectMatch_Alpine(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// alpine 3.18 fix: openssl 3.1.4-r5
			p := dbtest.NewPackage("openssl", "3.1.4-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherApk_DirectMatch_Wolfi(t *testing.T) {
	dbtest.DBs(t, "wolfi-rolling").
		SelectOnly("wolfi:rolling/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// wolfi fix: openssl 3.2.1-r0
			p := dbtest.NewPackage("openssl", "3.1.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.WolfiRolling).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherApk_IndirectMatchBySource verifies the upstream/origin
// indirection path: alpine secdb keys CVE-2024-0727 by openssl; libssl3 is
// a subpackage whose apk origin is openssl, so the match resolves via
// findMatchesForOriginPackage.
func TestMatcherApk_IndirectMatchBySource(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("libssl3", "3.1.4-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithUpstream("openssl", "").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherApk_SecdbMatchesWithoutCpe verifies that a package with no
// CPEs still gets secdb matches: cpeMatchesWithoutSecDBFixes returns
// internal.ErrEmptyCPEMatch which the matcher swallows so the secdb path
// continues uninterrupted.
func TestMatcherApk_SecdbMatchesWithoutCpe(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "3.1.4-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// === fixed-version → DistroPackageFixed ignore (no match) ===

func TestMatcherApk_FixedVersionProducesIgnore_Alpine(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("openssl-alpine-fixed")
			p := dbtest.NewPackage("openssl", "3.1.4-r5", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

func TestMatcherApk_FixedVersionProducesIgnore_Wolfi(t *testing.T) {
	dbtest.DBs(t, "wolfi-rolling").
		SelectOnly("wolfi:rolling/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("openssl-wolfi-fixed")
			p := dbtest.NewPackage("openssl", "3.2.1-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.WolfiRolling).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_FixedVersionInUpstreamProducesIgnore verifies that when a
// binary apk package's upstream is at or past the secdb fix, the
// DistroPackageFixed ignore is emitted against the binary package's ID
// (catalogPkg) - not the synthetic upstream - so consumers can suppress
// language-ecosystem matches that overlap the binary by file ownership.
func TestMatcherApk_FixedVersionInUpstreamProducesIgnore(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("libssl3-fixed")
			p := dbtest.NewPackage("libssl3", "3.1.4-r5", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithUpstream("openssl", "3.1.4-r5").
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// === NAK → Explicit APK NAK + DistroPackageFixed ignores ===

// TestMatcherApk_NakProducesIgnore_Alpine verifies the NAK path: alpine
// CVE-2019-6470 lists bind with Version="0", which the v6 OS transformer
// turns into a "< 0" ApkFormat constraint. The matcher emits two ignores
// per NAK - one DistroPackageFixed via the shared MatchPackageByDistro
// fixed/unaffected ownership path, and one apk-specific Explicit APK NAK
// via findNaksForPackage. Both point at the same package + CVE.
func TestMatcherApk_NakProducesIgnore_Alpine(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2019-6470").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("bind-pkg")
			p := dbtest.NewPackage("bind", "9.16.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				Build()

			ignores := db.Match(t, &matcher, p).Ignores()
			ignores.SelectRelatedPackageIgnore(reasonExplicitApkNak, "CVE-2019-6470").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			ignores.SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2019-6470").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

func TestMatcherApk_NakProducesIgnore_Wolfi(t *testing.T) {
	// wolfi CVE-2024-47535 lists akhq (and others) with Version="0".
	dbtest.DBs(t, "wolfi-rolling").
		SelectOnly("wolfi:rolling/CVE-2024-47535").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("akhq-pkg")
			p := dbtest.NewPackage("akhq", "0.25.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.WolfiRolling).
				Build()

			ignores := db.Match(t, &matcher, p).Ignores()
			ignores.SelectRelatedPackageIgnore(reasonExplicitApkNak, "CVE-2024-47535").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			ignores.SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-47535").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_NakInUpstreamProducesIgnore verifies that when the secdb
// NAK applies to an upstream/origin package, the ignores still point at
// the binary package's ID. The bind alpine 3.18 NAK applies to source
// "bind"; a binary named bind-tools would be treated as a subpackage.
func TestMatcherApk_NakInUpstreamProducesIgnore(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2019-6470").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("bind-tools-pkg")
			p := dbtest.NewPackage("bind-tools", "9.16.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithUpstream("bind", "").
				Build()

			ignores := db.Match(t, &matcher, p).Ignores()
			ignores.SelectRelatedPackageIgnore(reasonExplicitApkNak, "CVE-2019-6470").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			ignores.SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2019-6470").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_UnknownPackageProducesNothing verifies that a package the
// secdb has no record of (and which has no CPEs to match NVD) yields
// neither matches nor ignores - the search-miss case the language-ignore
// chain relies on so that GHSAs aren't suppressed for packages the distro
// doesn't ship.
func TestMatcherApk_UnknownPackageProducesNothing(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("something-obscure", "1.0.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// === NVD CPE matching alongside secdb ===

// TestMatcherApk_NvdDedupedBySecdb verifies that when a CVE is present in
// both secdb and NVD and both records consider the package vulnerable, only
// the secdb record is returned - the apk matcher trusts secdb as
// authoritative and drops the duplicate NVD CPE finding.
func TestMatcherApk_NvdDedupedBySecdb(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727", "CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "3.1.4-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:openssl:openssl:3.1.4-r0:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherApk_NvdDroppedWhenSecdbHasFix verifies that when secdb knows
// about a CVE and considers the package fixed, the NVD CPE record is
// dropped even if NVD still considers the upstream version vulnerable. The
// only output is a DistroPackageFixed ignore from the secdb path.
func TestMatcherApk_NvdDroppedWhenSecdbHasFix(t *testing.T) {
	// alpine fix: openssl 3.1.4-r5. NVD CVE-2024-0727 lists openssl in
	// [3.1.0, 3.1.5), so 3.1.4 still matches the NVD CPE range - this is
	// exactly the case the secdb-trumps-NVD logic exists to suppress.
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727", "CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("openssl-fixed-with-cpe")
			p := dbtest.NewPackage("openssl", "3.1.4-r5", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:openssl:openssl:3.1.4-r5:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_NvdMatchWhenSecdbHasNoCveEntry verifies the NVD-only path
// of cpeMatchesWithoutSecDBFixes: CVE-2014-0224 affects openssl in
// [1.0.1, 1.0.1h) per NVD, but alpine 3.18 secdb doesn't carry a record
// for it. The matcher returns it as a CPEMatch alongside the unrelated
// secdb CVE-2024-0727 finding for the same package.
func TestMatcherApk_NvdMatchWhenSecdbHasNoCveEntry(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727", "CVE-2014-0224", "CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("openssl-1.0.1f")
			p := dbtest.NewPackage("openssl", "1.0.1f-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:openssl:openssl:1.0.1f-r0:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			// secdb path supplies CVE-2024-0727
			findings.SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
			// NVD-only path supplies CVE-2014-0224
			findings.SelectMatch("CVE-2014-0224").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()

			// CVE-2024-0727 is in NVD too; v1.0.1f is outside any of NVD's
			// vulnerable ranges for that CVE, so MatchPackageByCPEs flags
			// it as "CPE not vulnerable" (separate from the secdb match).
			findings.Ignores().
				SelectRelatedPackageIgnore(reasonCPENotVulnerable, "CVE-2024-0727").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_NvdFixDroppedWhenNoSecdbEntry verifies the apk-specific
// behavior of stripping NVD's fix info on NVD-only matches: the matcher
// treats the secdb as the authoritative source of fix versions for apk
// packages, so when secdb has no record of a CVE it sets the NVD record's
// Fix to vulnerability.FixStateUnknown rather than letting NVD's
// upstream-only fix version leak through.
func TestMatcherApk_NvdFixDroppedWhenNoSecdbEntry(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("CVE-2014-0224").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "1.0.1f-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:openssl:openssl:1.0.1f-r0:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2014-0224").
				HasFix(vulnerability.FixStateUnknown).
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
}

// TestMatcherApk_NvdMatchAppliesVersionFiltering verifies that NVD CVEs
// outside the package's vulnerable range are filtered out:
// CVE-2014-0224's openssl ranges max at 1.0.1h, so an openssl 3.1.4-r0
// package never matches CVE-2014-0224 even though both share a CPE
// product. The fixture has CVE-2014-0224 but the matcher should not
// surface it for this version.
func TestMatcherApk_NvdMatchAppliesVersionFiltering(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("3.18/CVE-2024-0727", "CVE-2014-0224", "CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("openssl-3.1.4")
			p := dbtest.NewPackage("openssl", "3.1.4-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:openssl:openssl:3.1.4-r0:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()

			// CVE-2014-0224 is fetched by CPE but its versionEndExcluding
			// is 1.0.1h; openssl 3.1.4 is past that, so the version filter
			// drops it - which surfaces as a "CPE not vulnerable" ignore.
			findings.Ignores().
				SelectRelatedPackageIgnore(reasonCPENotVulnerable, "CVE-2014-0224").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherApk_NvdMatchBySourceIndirection verifies that NVD CPE matches
// can reach a binary apk package only via its upstream/origin package
// when the binary's own CPE product differs from the upstream's. The
// binary libssl3's CPE (cpe:2.3:a:libssl3:libssl3:...) does not match
// NVD's openssl record, but pkg.UpstreamPackages rewrites the CPE -
// substituting the binary name for the upstream name - so the synthesized
// upstream CPE (cpe:2.3:a:openssl:openssl:...) does match. This ensures
// only the indirect match path produces the finding.
func TestMatcherApk_NvdMatchBySourceIndirection(t *testing.T) {
	dbtest.DBs(t, "alpine318").
		SelectOnly("CVE-2014-0224").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("libssl3", "1.0.1f-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithUpstream("openssl", "").
				WithCPE("cpe:2.3:a:libssl3:libssl3:1.0.1f-r0:*:*:*:*:*:*:*").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2014-0224").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})
}

// TestMatcherApk_NvdCanceledByUpstreamSecdbNak verifies that an upstream
// secdb NAK suppresses an NVD CPE match for the same CVE:
// cpeMatchesWithoutSecDBFixes pulls upstream secdb entries when checking
// the secdb-says-not-vulnerable filter, so a wolfi NAK on the akhq origin
// (CVE-2024-47535 with Version="0") cancels the NVD CPE match for the
// netty-common CPE on a downstream binary package.
func TestMatcherApk_NvdCanceledByUpstreamSecdbNak(t *testing.T) {
	dbtest.DBs(t, "wolfi-rolling").
		SelectOnly("wolfi:rolling/CVE-2024-47535", "CVE-2024-47535").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("akhq-bin")
			p := dbtest.NewPackage("akhq-bin", "0.25.0-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(dbtest.WolfiRolling).
				WithUpstream("akhq", "").
				WithCPE("cpe:2.3:a:io.netty:netty-common:0.25.0-r0:*:*:*:*:maven:*:*").
				Build()

			findings := db.Match(t, &matcher, p)

			// no NVD match emerges - the upstream NAK on akhq cancels the
			// netty-common CPE finding before deduplicateMatches runs.
			findings.DoesNotHaveAnyVulnerabilities("CVE-2024-47535")

			// the upstream NAK still produces both apk-NAK and
			// DistroPackageFixed ignores keyed to the catalog package.
			ignores := findings.Ignores()
			ignores.SelectRelatedPackageIgnore(reasonExplicitApkNak, "CVE-2024-47535").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			ignores.SelectRelatedPackageIgnore(reasonDistroPackageFixed, "CVE-2024-47535").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// === architecture qualifier filtering (CG OSV records) ===
//
// The chainguard-rolling fixture has CGA-22hv-wp9q-4779, which emits
// AffectedPackageHandles with an Architecture qualifier per row:
//   - langfuse-3-worker      / Chainguard / arch=x86_64   / fixed:3.153.0-r0
//   - langfuse-fips-3-worker / Chainguard / arch=x86_64   / fixed:3.152.0-r0
//   - langfuse-3-worker      / Wolfi      / arch=aarch64  / fixed:3.153.0-r0
//
// These tests pin down architectureQualifier.Satisfied at the matcher level:
// the qualifier filters vuln entries whose arch disagrees with the scanned
// package, and is inert (passthrough) when the package has no arch. The
// existing wolfi/alpine secdb tests don't exercise this path because the OS
// transformer never emits Architecture qualifiers.

// TestMatcherApk_ArchFilter_MatchWhenArchAgrees confirms the happy path:
// arch on the package equals the qualifier's arch, so Satisfied returns
// true and the vuln surfaces as a normal distro match.
func TestMatcherApk_ArchFilter_MatchWhenArchAgrees(t *testing.T) {
	dbtest.DBs(t, "chainguard-rolling").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		// fix is 3.153.0-r0; 3.152.0-r0 is below, so the apk constraint matches
		p := dbtest.NewPackage("langfuse-3-worker", "3.152.0-r0", syftPkg.ApkPkg).
			WithDistro(dbtest.ChainguardRolling).
			WithArchitecture("x86_64").
			Build()

		// package p is affected by this vulnerability on this architecture
		db.Match(t, &matcher, p).
			SelectMatch("CGA-22hv-wp9q-4779").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
	})
}

// TestMatcherApk_ArchFilter_IgnoreWhenArchAgrees is the pair of
// MatchWhenArchAgrees: same package, same arch, but a version past the
// fix. The arch qualifier still passes so the fix path runs and emits
// one DistroPackageFixed ignore per identifier (CGA id + aliases).
// Cross-checks that arch filtering doesn't short-circuit the
// fixed-version ignore emission.
func TestMatcherApk_ArchFilter_IgnoreWhenArchAgrees(t *testing.T) {
	dbtest.DBs(t, "chainguard-rolling").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		// fix is 3.153.0-r0; 3.153.1-r0 is over the fix, so the matcher emits
		// no match but does emit one DistroPackageFixed ignore per identifier
		// (the CGA id plus its CVE/GHSA aliases) so consumers can suppress
		// language-ecosystem findings that overlap by file ownership.
		pkgID := pkg.ID("langfuse-past-fix")
		p := dbtest.NewPackage("langfuse-3-worker", "3.153.1-r0", syftPkg.ApkPkg).
			WithID(pkgID).
			WithDistro(dbtest.ChainguardRolling).
			WithArchitecture("x86_64").
			Build()

		// vulnerability fixed this pkg-version for this architecture
		db.Match(t, &matcher, p).Ignores().
			SelectRelatedPackageIgnores(reasonDistroPackageFixed,
				"CGA-22hv-wp9q-4779",
				"CVE-2026-24398",
				"GHSA-r354-f388-2fhh").
			ForPackage(pkgID).
			WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
	})
}

// TestMatcherApk_ArchFilter_NoMatchWhenArchDisagrees is the load-bearing case:
// the package's arch is aarch64 but the only Chainguard APH for this name has
// arch=x86_64, so OnlyQualifiedPackages drops it before the version check ever
// runs. No match, no ignore (the vuln is filtered before reaching the fix
// path that would emit a DistroPackageFixed ignore).
func TestMatcherApk_ArchFilter_NoMatchWhenArchDisagrees(t *testing.T) {
	dbtest.DBs(t, "chainguard-rolling").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("langfuse-3-worker", "3.152.0-r0", syftPkg.ApkPkg).
			WithDistro(dbtest.ChainguardRolling).
			WithArchitecture("aarch64"). // mismatch: Chainguard APH says x86_64
			Build()

		// no records match chainguard - aarch64
		db.Match(t, &matcher, p).IsEmpty()
	})
}

// TestMatcherApk_ArchFilter_InertWhenPackageHasNoArch documents the
// passthrough branch of Satisfied(p): if p.Arch == "" the qualifier is
// treated as inert, preserving pre-change behavior for input paths that
// don't populate Arch. Without this branch every existing test using
// WithDistro-but-not-WithArchitecture would regress against arch-tagged
// providers like chainguard.
func TestMatcherApk_ArchFilter_InertWhenPackageHasNoArch(t *testing.T) {
	dbtest.DBs(t, "chainguard-rolling").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("langfuse-3-worker", "3.152.0-r0", syftPkg.ApkPkg).
			WithDistro(dbtest.ChainguardRolling).
			// Architecture intentionally not set.
			Build()

		// package p is affected by this vulnerability because the qualifier is inert
		// when the package has no arch
		db.Match(t, &matcher, p).
			SelectMatch("CGA-22hv-wp9q-4779").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
	})
}

// TestMatcherApk_ArchFilter_WolfiArchAgrees mirrors the first test against
// the Wolfi side of the same CGA record. Beyond exercising arch=aarch64,
// this also confirms the per-ecosystem OS row split: the matcher must reach
// the Wolfi APH (not the Chainguard APH) when the package's distro is Wolfi.
func TestMatcherApk_ArchFilter_WolfiArchAgrees(t *testing.T) {
	dbtest.DBs(t, "chainguard-rolling").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}
		p := dbtest.NewPackage("langfuse-3-worker", "3.152.0-r0", syftPkg.ApkPkg).
			WithDistro(dbtest.WolfiRolling).
			WithArchitecture("aarch64").
			Build()

		// wolfi package p is affected by this vulnerability on this architecture
		db.Match(t, &matcher, p).
			SelectMatch("CGA-22hv-wp9q-4779").
			SelectDetailByType(match.ExactDirectMatch).
			AsDistroSearch()
	})
}

// === pure-unit tests of apk-specific predicates (no provider involved) ===

// Test_nakConstraint covers the search.ByConstraintFunc that
// findNaksForPackage uses to pick out only the apk "< 0" sentinel
// constraint - independent of the matcher's fixture-driven flow.
func Test_nakConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   vulnerability.Vulnerability
		matches bool
	}{
		{
			name: "matches apk",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.ApkFormat),
			},
			matches: true,
		},
		{
			name: "not match due to type",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.SemanticFormat),
			},
			matches: false,
		},
		{
			name: "not match",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, _, err := nakConstraint.MatchesVulnerability(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}
