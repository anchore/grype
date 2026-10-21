package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoSymbols_VNRangeGluedPrerelease guards a fixed false negative
// where a github.com/redis/go-redis/v9 @ 9.6.0 binary matched nothing at all,
// despite being genuinely affected (fixed in 9.6.3) and actually reachable.
//
// The mechanics (GO-2025-3540 / CVE-2025-29923 / GHSA-92cp-5422-2mw7):
//   - the merge marks the GO record's /v9 rows "covered" (GHSA-92cp also lists
//     github.com/redis/go-redis/v9) and drops them, leaving the GHSA as the record
//     that must match 9.6.0.
//   - GHSA-92cp's covering range is >= 9.6.0b1, < 9.6.3. The "9.6.0b1" bound is a
//     non-canonical prerelease (glued tag, no "-" separator); go modules never
//     publish it (the real beta tag is v9.6.0-beta.1), it is only advisory data.
//   - grype's golang comparator could not parse "9.6.0b1", so the whole range went
//     inert and 9.6.0 matched nothing.
//
// The fix normalizes a glued-on prerelease tag ("9.6.0b1" -> "9.6.0-b1", see
// grype/version/golang_version.go), so the range parses and correctly covers 9.6.0.
// This surfaced as the single adjudicated grype false negative across a 62-subject
// differential corpus.
func TestMatcherGolang_GoSymbols_VNRangeGluedPrerelease(t *testing.T) {
	const (
		goRedisGo   = "GO-2025-3540"        // /v9 < 9.6.3 rows are deduped onto the GHSA
		goRedisGHSA = "GHSA-92cp-5422-2mw7" // surviving twin whose >= 9.6.0b1 range now parses
	)

	// 9.6.0 is inside the GHSA's (normalized) >= 9.6.0-b1, < 9.6.3 window.
	const affectedGoRedisVersion = "v9.6.0"

	dbtest.DBs(t, "govulndb-and-ghsa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		// module-level scan (no symbols): isolates the version-range decision from
		// symbol scoping. The vuln genuinely applies (fixed in 9.6.3), so it must be
		// reported. The GO /v9 rows were deduped onto GHSA-92cp, so the match lands
		// under the GHSA namespace (GO-2025-3540 rides along as a related vuln).
		p := dbtest.NewPackage("github.com/redis/go-redis/v9", affectedGoRedisVersion, syftPkg.GoModulePkg).
			WithLanguage(syftPkg.Go).
			WithMetadata(pkg.GolangBinMetadata{}).
			Build()

		findings := db.Match(t, matcher, p)

		findings.SelectMatch(goRedisGHSA).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
	})
}
