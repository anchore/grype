package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoSymbols_GHSATwinBypass documents a WEAK POINT in the
// build-time govulndb<->GHSA merge (grype/db/v6/build/govulndb_merge.go): when a
// GO-* record does not directly alias its GHSA twin, the symbol scope never
// reaches the GHSA record, so the GHSA matches at plain module granularity and
// reproduces exactly the false positives the gosymbols feature exists to remove.
//
// These tests assert the CORRECT (idealic) behavior and are EXPECTED TO FAIL on
// the current build until the merge bridges GO and GHSA by their shared CVE (or
// the qualifier is applied across an advisory's whole alias group). Do not
// "fix" them by weakening the assertion — they should be made to pass by fixing
// the merge.
//
// Root cause (confirmed against real data):
//   - handleEntry() derives the GHSA records to patch from ghsaAliasKeys(), which
//     reads only GHSA-prefixed aliases off the GO record's own alias list.
//   - Recent govulndb records for golang.org/x/crypto/ssh alias ONLY the CVE, not
//     the GHSA, e.g. GO-2026-5013 -> ["CVE-2026-46597"] and
//     GO-2026-5005 -> ["CVE-2026-39833"]. GO-2024-3321 is the exception that
//     merges cleanly because it happens to also list "GHSA-v778-237x-gjrc".
//   - The GHSA twin still lands in the DB via the github feed (CVE-linked), is
//     held by the merger (hasGoModulePackages), but no GO record names it, so it
//     is written UNPATCHED at module level.
//
// Empirical proof: a binary linking only golang.org/x/crypto/sha3 - with
// nothing from the vulnerable ssh sub-package reachable - still drew 14
// grype findings, all GHSA-* x/crypto ssh CVEs, while their GO-* twins were
// correctly suppressed and absent from the output.
//
// The fixture pair modeling this (both hand-authored, see db.yaml):
//   - govulndb GO-2026-5013: golang.org/x/crypto, imports scoped to
//     golang.org/x/crypto/ssh (whole-package), aliases only CVE-2026-46597.
//   - github  GHSA-46q7-xr5m-cr77: golang.org/x/crypto module-level, < 0.35.0,
//     same CVE-2026-46597, no symbol scope. (Synthetic GHSA id: the exact real
//     id for this CVE is not needed to exercise the merge weak point.)
func TestMatcherGolang_GoSymbols_GHSATwinBypass(t *testing.T) {
	const (
		sshPanicGo   = "GO-2026-5013"        // scoped to x/crypto/ssh; aliases only CVE-2026-46597 (no GHSA)
		sshPanicGHSA = "GHSA-46q7-xr5m-cr77" // x/crypto module-level twin, CVE-linked only -> never symbol-patched
	)

	// a version inside both the GO record's (< 0.35.0) and GHSA's (< 0.35.0) windows.
	const vulnerableXCryptoVersion = "v0.20.0"

	dbtest.DBs(t, "govulndb-and-ghsa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		t.Run("x/crypto binary using only sha3 must not match the ssh advisory via EITHER namespace", func(t *testing.T) {
			// the sha3-only reproduction: links golang.org/x/crypto but never the
			// vulnerable ssh sub-package, so nothing vulnerable is reachable.
			// The GO record is correctly suppressed (ssh import absent); the ideal
			// result is no match at all. Today the unpatched GHSA twin matches at
			// module granularity -> this assertion FAILS, exposing the bypass.
			p := dbtest.NewPackage("golang.org/x/crypto", vulnerableXCryptoVersion, syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"golang.org/x/crypto/sha3": {"New256", "Sum256"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			// ideal: a binary that never links the vulnerable ssh sub-package
			// matches nothing. Today the unpatched GHSA twin matches at module
			// granularity, so this FAILS with GHSA-46q7-xr5m-cr77 present.
			findings.IsEmpty()
		})

		t.Run("x/crypto binary using ssh still matches (positive control)", func(t *testing.T) {
			// genuinely links the vulnerable golang.org/x/crypto/ssh package, so it
			// SHOULD be flagged. Both namespaces firing is correct here: the GO
			// record matches on the ssh import, and the GHSA twin also matches. This
			// passes today and guards against a fix that over-suppresses real users.
			p := dbtest.NewPackage("golang.org/x/crypto", vulnerableXCryptoVersion, syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"golang.org/x/crypto/ssh": {"NewServerConn", "ServerConfig.PublicKeyCallback"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.SelectMatch(sshPanicGo).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
			findings.SelectMatch(sshPanicGHSA).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
		})
	})
}
