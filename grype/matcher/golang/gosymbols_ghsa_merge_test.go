package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoSymbols_GHSAMerge exercises the build-time merge of
// govulndb symbol information onto GHSA records (grype/db/v6/build/
// govulndb_merge.go) end to end, against a DB built from BOTH the govulndb and
// github providers — the production shape, where most golang.org/x/* and
// third-party advisories exist in both feeds.
//
// Symbol evidence comes from two tiers. The x/net and stdlib scenarios reuse
// TestMatcherGolang_GoSymbols's compiled go-binary fixtures, which prove the
// contract between syft's real symbol capture and grype's normalization. The
// third-party scenarios (gjson, aws-sdk-go) exercise DB-side merge and range
// behavior only, so they use hand-written symbol lists (import-path qualified,
// in govulndb's normalized convention — the form the provider stores) rather
// than compiling a fixture per scenario.
//
// The govulndb-and-ghsa fixture pairs:
//   - GO-2022-0969 with GHSA-69cg-p879-7622, which lists golang.org/x/net AND
//     the golang.org/x/net/http2 sub-package as separate affected packages: both
//     GHSA packages gain the x/net symbols, the GO record keeps only stdlib
//     (no GHSA lists the stdlib module itself, so stdlib is never dropped).
//   - GO-2021-0265 with two GHSAs for github.com/tidwall/gjson: the active one
//     (GHSA-ppj4-34rq-v8j9) gains the gjson symbols and covers the GO record,
//     which is dropped from the DB; GHSA-c9gm-7rfj-8w5h is withdrawn upstream
//     (a duplicate advisory, as in the real data) so it is neither patched nor
//     allowed to cover, and — being rejected — never matches.
//   - GO-2023-1840 (stdlib-only, whole-package "runtime") with no GHSA alias:
//     written unchanged.
//   - GO-2024-3312 with GHSA-4c49-9fpc-hc3v for github.com/canonical/lxd: the
//     GHSA range is pinned to the pseudo-version of the fix commit, which no
//     real tagged release can ever satisfy; the merge replaces it with the
//     govulndb custom_ranges tag-space window (< 5.21.2) and patches the lxd
//     symbols on.
//   - GO-2021-0076 with GHSA-gxhv-3hwf-wjp9 for github.com/evanphx/json-patch:
//     a +incompatible module; the GHSA's plain-semver windows must match
//     v3.0.0+incompatible binaries, gated by the merged Patch.Apply symbols.
//
// The headline behavior: the CVE no longer resurfaces through an unfiltered
// GHSA record. A binary that merely links golang.org/x/net or gjson without
// using the vulnerable symbols matches nothing at all — the GHSA record itself
// is now symbol-filtered — while binaries that do use them still match via the
// GHSA record.
func TestMatcherGolang_GoSymbols_GHSAMerge(t *testing.T) {
	const (
		httpServerDoSGHSA = "GHSA-69cg-p879-7622" // golang.org/x/net(+/http2) server DoS; symbols merged from GO-2022-0969
		httpServerDoSGo   = "GO-2022-0969"        // survives with only its stdlib affected package
		runtimeWholePkg   = "GO-2023-1840"        // stdlib "runtime", whole-package, no GHSA alias
		gjsonReDoSGo      = "GO-2021-0265"        // fully GHSA-covered -> dropped from the DB
		gjsonReDoSGHSA    = "GHSA-ppj4-34rq-v8j9" // active gjson GHSA; patched with symbols from GO-2021-0265
		gjsonWithdrawn    = "GHSA-c9gm-7rfj-8w5h" // withdrawn upstream (duplicate advisory): not patched, never matches
		s3cryptoGHSA      = "GHSA-7f33-f4f5-xwgw" // aws-sdk-go < 1.34.0; symbols merged from GO-2022-0635
		s3cryptoGo        = "GO-2022-0635"        // open-ended range (no fix per govulndb) -> fully covered, dropped
		lxdGHSA           = "GHSA-4c49-9fpc-hc3v" // lxd; pseudo-version range replaced by GO-2024-3312's < 5.21.2
		lxdGo             = "GO-2024-3312"        // fully GHSA-covered -> dropped from the DB
		jsonPatchGHSA     = "GHSA-gxhv-3hwf-wjp9" // json-patch (+incompatible module); symbols merged from GO-2021-0076
		jsonPatchGo       = "GO-2021-0076"        // fully GHSA-covered -> dropped from the DB
		goRedisGHSA       = "GHSA-92cp-5422-2mw7" // go-redis /v9 rows; symbols merged from GO-2025-3540
		goRedisGo         = "GO-2025-3540"        // /v9 rows dropped; base and /v7 /v8 rows survive
		ginCoverageGHSA   = "GHSA-3vp4-m3rf-835h" // gin CVE-2023-26125; NO govulndb twin -> survives unpatched, module-level
	)

	// see TestMatcherGolang_GoSymbols for why these versions are pinned
	const vulnerableStdlibVersion = "go1.18.0"
	const vulnerableXNetVersion = "v0.0.0-20220225172249-27dd8689420f"

	dbtest.DBs(t, "govulndb-and-ghsa").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		expectMatches := func(t *testing.T, f *dbtest.FindingsAssertion, ids ...string) {
			t.Helper()
			for _, id := range ids {
				f.SelectMatch(id).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
			}
		}

		t.Run("x/net http2 server binary matches via the symbol-patched GHSA", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-xnet-http2server").
				Package("golang.org/x/net").
				WithVersion(vulnerableXNetVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// the GHSA gained the vulnerable symbols and this binary uses them;
			// the GO record's x/net package was dropped, so the GHSA is the only match.
			expectMatches(t, findings, httpServerDoSGHSA)
			findings.DoesNotHaveAnyVulnerabilities(httpServerDoSGo)
		})

		t.Run("x/net html-only binary matches nothing - the GHSA is symbol-filtered too", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-xnet-html").
				Package("golang.org/x/net").
				WithVersion(vulnerableXNetVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// before the merge this binary matched the unfiltered GHSA record by
			// module name; with the symbols patched on, the false positive is gone.
			findings.IsEmpty()
		})

		t.Run("stdlib server binary still matches the GO record - stdlib is never dropped", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-httpserver").
				Package("stdlib").
				WithVersion(vulnerableStdlibVersion).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, httpServerDoSGo, runtimeWholePkg)
		})

		t.Run("stdlib client-only binary is suppressed on the pruned GO record", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-httpclient").
				Package("stdlib").
				WithVersion(vulnerableStdlibVersion).
				Build()

			findings := db.Match(t, matcher, p)

			findings.DoesNotHaveAnyVulnerabilities(httpServerDoSGo)
			expectMatches(t, findings, runtimeWholePkg)
		})

		t.Run("3rd-party binary using a vulnerable symbol matches the patched GHSA", func(t *testing.T) {
			// gjson v1.9.2 is inside both GHSAs' < 1.9.3 window; the symbols are what
			// a binary calling gjson.Get carries (the exported entrypoint plus the
			// internals it pulls in — parseObject/queryMatches are themselves on
			// GO-2021-0265's symbol list)
			p := dbtest.NewPackage("github.com/tidwall/gjson", "v1.9.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/tidwall/gjson": {"Get", "parseObject", "queryMatches", "Result.String"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			// gjson.Get is present -> the active, symbol-patched GHSA matches;
			// the fully covered GO record is not in the DB at all, and the
			// withdrawn duplicate GHSA is rejected so it never matches. The match
			// detail reports exactly the intersection of the binary's symbols and
			// GO-2021-0265's list (Result.String is not on the advisory, so it is
			// excluded), sorted, in govulndb (advisory) convention.
			findings.SelectMatch(gjsonReDoSGHSA).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch().
				HasMatchedSymbols(
					"github.com/tidwall/gjson.Get",
					"github.com/tidwall/gjson.parseObject",
					"github.com/tidwall/gjson.queryMatches",
				)
			findings.DoesNotHaveAnyVulnerabilities(gjsonReDoSGo, gjsonWithdrawn)
		})

		t.Run("3rd-party binary avoiding vulnerable symbols matches nothing", func(t *testing.T) {
			// links vulnerable gjson but only uses gjson.Valid (and the internals it
			// pulls in), none of which are on GO-2021-0265's symbol list; before the
			// merge the unfiltered GHSA records matched this binary by module name
			p := dbtest.NewPackage("github.com/tidwall/gjson", "v1.9.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/tidwall/gjson": {"Valid", "validpayload", "validany"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		// s3cryptoSymbols is what a binary using the S3 crypto client carries (import path -> raw
		// local names, as syft captures them): the vulnerable constructor (on GO-2022-0635's symbol
		// list) plus surrounding SDK surface that is not.
		s3cryptoSymbols := map[string][]string{
			"github.com/aws/aws-sdk-go/service/s3/s3crypto": {"NewDecryptionClient", "(*DecryptionClient).GetObject"},
			"github.com/aws/aws-sdk-go/aws/session":         {"NewSession"},
		}

		t.Run("current aws-sdk-go using vulnerable symbols is out of the GHSA range - no match", func(t *testing.T) {
			// GO-2022-0635 is open-ended in govulndb (introduced: 0, no fix), so
			// govulncheck reports EVERY aws-sdk-go version — including a current
			// one — as affected. The aliased GHSA bounds the range at < 1.34.0
			// (fixed 2020). The merged record carries the GHSA range, so the
			// vulnerable symbols being present does not matter here: the version
			// is fixed. This is the merged-data range win — the same
			// ranges-disagree-with-symbols shape as GO-2022-0274 /
			// GHSA-v95c-p5hm-xq8f (runc), where the GHSA is right because the fix
			// was backported to a release branch semver ranges cannot express.
			p := dbtest.NewPackage("github.com/aws/aws-sdk-go", "v1.55.8", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(s3cryptoSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("old aws-sdk-go using vulnerable symbols matches the patched GHSA", func(t *testing.T) {
			// inside the GHSA's < 1.34.0 window the merged record matches — but
			// only because this binary uses s3crypto.NewDecryptionClient.
			p := dbtest.NewPackage("github.com/aws/aws-sdk-go", "v1.33.0", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(s3cryptoSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, s3cryptoGHSA)
			findings.DoesNotHaveAnyVulnerabilities(s3cryptoGo)
		})

		t.Run("old aws-sdk-go not using s3crypto is suppressed by the merged symbols", func(t *testing.T) {
			// the GHSA alone flagged every aws-sdk-go binary below 1.34.0, even
			// ones that never touch the S3 crypto client — the dominant FP class
			// for one of the most-linked Go modules. With govulndb's symbols
			// merged on, symbol evidence without the vulnerable symbols suppresses
			// the match.
			p := dbtest.NewPackage("github.com/aws/aws-sdk-go", "v1.33.0", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/aws/aws-sdk-go/service/s3": {"New", "(*S3).GetObject"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		// lxdSymbols is what an lxd daemon binary carries (import path -> raw local names): the
		// vulnerable project resource listing function (on GO-2024-3312's symbol list) plus other
		// lxd internals that are not.
		lxdSymbols := map[string][]string{
			"github.com/canonical/lxd/lxd":        {"allowProjectResourceList", "projectResourceList"},
			"github.com/canonical/lxd/shared/api": {"NewURL"},
		}

		t.Run("lxd at a real tagged release matches via the replaced pseudo-version range", func(t *testing.T) {
			// GHSA-4c49-9fpc-hc3v as published is pinned to the pseudo-version of
			// the fix commit: "< 0.0.0-20240708073652-5a492a3f0036". LXD does not
			// follow Go module versioning, so that is the only version GitHub can
			// name — but under semver ordering EVERY real tagged release (v5.21.1,
			// v5.21.0, …) sorts far above v0.0.0-…, meaning the raw GHSA range can
			// never match a real tag: a guaranteed false negative for any SBOM
			// that reports the release version. GO-2024-3312 carries the same fix
			// in tag space (custom_ranges < 5.21.2), the merge swapped it in
			// (replaceGHSAPseudoVersionRanges), and v5.21.1 now matches.
			p := dbtest.NewPackage("github.com/canonical/lxd", "v5.21.1", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(lxdSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, lxdGHSA)
			findings.DoesNotHaveAnyVulnerabilities(lxdGo)
		})

		t.Run("lxd at the fixed release does not match the replaced range", func(t *testing.T) {
			// v5.21.2 is the tag-space fix from GO-2024-3312's custom_ranges; the
			// replaced range must exclude it even though the vulnerable symbol is
			// present.
			p := dbtest.NewPackage("github.com/canonical/lxd", "v5.21.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(lxdSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("lxd binary not using the vulnerable symbol is suppressed", func(t *testing.T) {
			// inside the replaced range, but without allowProjectResourceList the
			// merged symbols suppress the match — range replacement and symbol
			// filtering compose.
			p := dbtest.NewPackage("github.com/canonical/lxd", "v5.21.1", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/canonical/lxd/lxd":        {"main"},
					"github.com/canonical/lxd/shared/api": {"NewURL"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		// jsonPatchSymbols is what a binary applying JSON patches carries (import path -> raw local
		// names): the vulnerable entrypoints (Patch.Apply and the partialArray.add internal it
		// reaches, both on GO-2021-0076's symbol list) plus surrounding API surface that is not.
		jsonPatchSymbols := map[string][]string{
			"github.com/evanphx/json-patch": {"Patch.Apply", "partialArray.add", "DecodePatch"},
		}

		t.Run("+incompatible binary using Patch.Apply matches the patched GHSA", func(t *testing.T) {
			// json-patch ships v3 tags without a /v3 module path, so binaries
			// report v3.0.0+incompatible while GHSA-gxhv-3hwf-wjp9's window is
			// plain semver (">= 3.0.0, < 3.0.1-0.20180525145409-4c9aadca8f89").
			// +incompatible is semver build metadata — ignored for precedence — so
			// the golang comparator must place v3.0.0+incompatible inside that
			// window. This is the non-standard-versioning + symbol-matching combo:
			// the version says vulnerable AND the binary uses Patch.Apply.
			p := dbtest.NewPackage("github.com/evanphx/json-patch", "v3.0.0+incompatible", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(jsonPatchSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, jsonPatchGHSA)
			findings.DoesNotHaveAnyVulnerabilities(jsonPatchGo)
		})

		t.Run("+incompatible binary avoiding vulnerable symbols matches nothing", func(t *testing.T) {
			// same vulnerable version, but the binary only creates/compares merge
			// patches — none of GO-2021-0076's symbols. Before the merge the
			// unfiltered GHSA matched any binary linking json-patch below the fix;
			// with the symbols patched on, no match.
			p := dbtest.NewPackage("github.com/evanphx/json-patch", "v3.0.0+incompatible", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/evanphx/json-patch": {"CreateMergePatch", "Equal"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("post-fix +incompatible version does not match", func(t *testing.T) {
			// v4.5.0+incompatible is above both GHSA windows (< 0.5.2 and
			// < 3.0.1-0.2018…): vulnerable symbols present, version fixed.
			p := dbtest.NewPackage("github.com/evanphx/json-patch", "v4.5.0+incompatible", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(jsonPatchSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		// goRedisSymbols is what a binary configuring a go-redis client carries (import path -> raw
		// local names): the vulnerable connection-setup path (baseClient.initConn is on
		// GO-2025-3540's symbol list) plus ordinary client surface that is not.
		goRedisSymbols := map[string][]string{
			"github.com/redis/go-redis/v9": {"(*baseClient).initConn", "NewClient", "(*Client).Ping"},
		}

		t.Run("/vN module major-version: the /v9 name is what binaries carry and it matches the patched GHSA", func(t *testing.T) {
			// Go module major versions are part of the module path, and therefore part of the
			// package name grype matches on: a binary built against go-redis 9.x embeds
			// "github.com/redis/go-redis/v9" in its buildinfo, and syft catalogs that name
			// verbatim (verified empirically through pkg.Provide against a real go-redis
			// binary). The GHSA lists only the /v9 rows — correctly, since /v9 is the only
			// module path ever published under this repo — so the merge drops the GO record's
			// /v9 rows and enriches the GHSA with the symbols. Matching is by exact name:
			// the GO record's surviving base-path row can never stand in for a /v9 package,
			// which is exactly why the merge must NOT drop /vN rows in favor of a shorter
			// path (that would leave every real go-redis binary matching nothing).
			//
			// v9.5.2 sits in the GHSA's >= 9.5.1, < 9.5.5 window. Note the sibling
			// >= 9.6.0b1, < 9.6.3 row is inert: "9.6.0b1" is malformed to the golang
			// comparator, and the comparison error is swallowed at match time — binaries in
			// that window are a known false negative, tracked in the custom_ranges
			// odd-version-strings follow-up issue.
			p := dbtest.NewPackage("github.com/redis/go-redis/v9", "v9.5.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(goRedisSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, goRedisGHSA)
			findings.DoesNotHaveAnyVulnerabilities(goRedisGo)
		})

		t.Run("/vN module at a fixed version does not match", func(t *testing.T) {
			// v9.7.3 is the fix for the last window; the other windows (< 9.5.5, < 9.6.3)
			// don't reach it either.
			p := dbtest.NewPackage("github.com/redis/go-redis/v9", "v9.7.3", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(goRedisSymbols).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("/vN module not using the vulnerable symbols is suppressed", func(t *testing.T) {
			// in-range, but the binary never touches the connection-setup path that
			// GO-2025-3540's symbols describe
			p := dbtest.NewPackage("github.com/redis/go-redis/v9", "v9.5.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithGoBinarySymbols(map[string][]string{
					"github.com/redis/go-redis/v9": {"NewClient", "(*Client).Get"},
				}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("/vN module major-version: the GO record survives with the rows the GHSA lacks", func(t *testing.T) {
			// The GHSA covered only the /v9 rows, so the GO record is still written carrying
			// its base-path, /v7, and /v8 rows. Those names were never published module paths
			// (v7/v8 of this client live at github.com/go-redis/redis/vN, a different repo
			// path entirely), so no real binary reports them — this probe is a DB-state
			// assertion that per-exact-name coverage kept the record, not a real-world
			// scenario. The /v8 row is a bare introduced:0 with no fix, which emits no
			// ranges: any version of a package by that name matches. (The base rows would
			// not serve here: their only range is the >= 9.6.0b1 custom floor, and that
			// version string is malformed to the golang comparator, leaving them inert.)
			p := dbtest.NewPackage("github.com/redis/go-redis/v8", "v8.11.5", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{}).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, goRedisGo)
			findings.DoesNotHaveAnyVulnerabilities(goRedisGHSA)
		})

		t.Run("3rd-party package without captured symbols falls back to module matching", func(t *testing.T) {
			// mirrors an SBOM produced without symbol capture (syft's default): the
			// patched GHSAs still match at module granularity, preserving
			// pre-feature behavior when there is no symbol evidence.
			p := dbtest.NewPackage("github.com/tidwall/gjson", "v1.9.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{}).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, gjsonReDoSGHSA)
		})

		t.Run("Go GHSA with no govulndb twin survives the merge and matches at module level", func(t *testing.T) {
			// GHSA-3vp4-m3rf-835h (gin, CVE-2023-26125) has no aliased GO record, so
			// the merge holds it (go-module package) but never patches or covers it.
			// It must still be written and match - grype's coverage advantage over a
			// govulndb-only view, where this vuln is invisible. Guards that un-twinned
			// held GHSAs are not dropped by the govulndb<->GHSA reconciliation.
			p := dbtest.NewPackage("github.com/gin-gonic/gin", "v1.8.0", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{}).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, ginCoverageGHSA)
		})
	})
}
