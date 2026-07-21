package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoSymbols_GHSATwinBypass guards a fixed WEAK POINT in the
// build-time govulndb<->GHSA merge (grype/db/v6/build/govulndb_merge.go): when a
// GO-* record does not directly alias its GHSA twin, the symbol scope must still
// reach the GHSA record via the shared CVE, so the GHSA does not match at plain
// module granularity and reproduce exactly the false positives the gosymbols
// feature exists to remove.
//
// The merge now bridges GO and GHSA by shared CVE (buildCVEIndex +
// aliasedGHSAKeys), so these assert the CORRECT behavior and pass. Do not
// "fix" a future regression by weakening the assertion — keep the merge
// bridging the whole alias group.
//
// Root cause that was fixed (confirmed against real data):
//   - handleEntry() derived the GHSA records to patch from GHSA-prefixed aliases
//     off the GO record's own alias list only.
//   - Recent govulndb records for golang.org/x/crypto/ssh alias ONLY the CVE, not
//     the GHSA, e.g. GO-2026-5013 -> ["CVE-2026-46597"] and
//     GO-2026-5005 -> ["CVE-2026-39833"]. GO-2024-3321 merged cleanly only
//     because it happens to also list "GHSA-v778-237x-gjrc".
//   - The GHSA twin lands in the DB via the github feed (CVE-linked) and is held
//     by the merger (hasGoModulePackages); with no GO record naming it directly
//     it was written UNPATCHED at module level until the CVE bridge.
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
		sshPanicGo   = "GO-2026-5013"        // scoped to x/crypto/ssh; aliases only CVE-2026-46597 (no GHSA) -> now covered by the twin and dropped
		sshPanicGHSA = "GHSA-46q7-xr5m-cr77" // x/crypto module-level twin, CVE-linked only -> symbol-patched via the CVE bridge
	)

	// a version inside both the GO record's (< 0.35.0) and GHSA's (< 0.35.0) windows.
	const vulnerableXCryptoVersion = "v0.20.0"

	dbtest.DBs(t, "govulndb-and-ghsa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		t.Run("x/crypto binary using only sha3 must not match the ssh advisory via EITHER namespace", func(t *testing.T) {
			// the sha3-only reproduction: links golang.org/x/crypto but never the
			// vulnerable ssh sub-package, so nothing vulnerable is reachable.
			// The GO record is correctly suppressed (ssh import absent), and the
			// GHSA twin now carries the same ssh scope via the CVE bridge, so
			// neither namespace matches.
			p := dbtest.NewPackage("golang.org/x/crypto", vulnerableXCryptoVersion, syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"golang.org/x/crypto/sha3": {"New256", "Sum256"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			// a binary that never links the vulnerable ssh sub-package matches
			// nothing: the GHSA twin is symbol-scoped by the merge, so it no longer
			// leaks at module granularity.
			findings.IsEmpty()
		})

		t.Run("x/crypto binary using ssh still matches (positive control)", func(t *testing.T) {
			// genuinely links the vulnerable golang.org/x/crypto/ssh package, so it
			// SHOULD be flagged. Once the merge bridges GO->GHSA by shared CVE the
			// GHSA twin is symbol-patched and the GO record's x/crypto package is
			// covered, so the GO record is dropped and the scoped GHSA is the only
			// match - the same dedup every clean-merge case produces (gjson, lxd,
			// aws-sdk-go). This guards against a fix that over-suppresses real users.
			p := dbtest.NewPackage("golang.org/x/crypto", vulnerableXCryptoVersion, syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"golang.org/x/crypto/ssh": {"NewServerConn", "ServerConfig.PublicKeyCallback"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			// the covered GO record is dropped; the symbol-scoped GHSA twin matches.
			findings.SelectMatch(sshPanicGHSA).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
		})
	})
}
