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
// behavior only, so they use hand-written symbol lists that mirror syft's
// capture naming (import-path qualified, pointer-receiver decorated) rather
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
				WithMetadata(pkg.GolangBinMetadata{Symbols: []string{
					"github.com/tidwall/gjson.Get",
					"github.com/tidwall/gjson.parseObject",
					"github.com/tidwall/gjson.queryMatches",
					"github.com/tidwall/gjson.Result.String",
				}}).
				Build()

			findings := db.Match(t, matcher, p)

			// gjson.Get is present -> the active, symbol-patched GHSA matches;
			// the fully covered GO record is not in the DB at all, and the
			// withdrawn duplicate GHSA is rejected so it never matches.
			expectMatches(t, findings, gjsonReDoSGHSA)
			findings.DoesNotHaveAnyVulnerabilities(gjsonReDoSGo, gjsonWithdrawn)
		})

		t.Run("3rd-party binary avoiding vulnerable symbols matches nothing", func(t *testing.T) {
			// links vulnerable gjson but only uses gjson.Valid (and the internals it
			// pulls in), none of which are on GO-2021-0265's symbol list; before the
			// merge the unfiltered GHSA records matched this binary by module name
			p := dbtest.NewPackage("github.com/tidwall/gjson", "v1.9.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{Symbols: []string{
					"github.com/tidwall/gjson.Valid",
					"github.com/tidwall/gjson.validpayload",
					"github.com/tidwall/gjson.validany",
				}}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		// s3cryptoSymbols is what a binary using the S3 crypto client carries:
		// the vulnerable constructor (on GO-2022-0635's symbol list) plus
		// surrounding SDK surface that is not.
		s3cryptoSymbols := []string{
			"github.com/aws/aws-sdk-go/service/s3/s3crypto.NewDecryptionClient",
			"github.com/aws/aws-sdk-go/service/s3/s3crypto.(*DecryptionClient).GetObject",
			"github.com/aws/aws-sdk-go/aws/session.NewSession",
		}

		t.Run("current aws-sdk-go using vulnerable symbols is out of the GHSA range - no match", func(t *testing.T) {
			// GO-2022-0635 is open-ended in govulndb (introduced: 0, no fix), so
			// govulncheck reports EVERY aws-sdk-go version — including a current
			// one — as affected. The aliased GHSA bounds the range at < 1.34.0
			// (fixed 2020). The merged record carries the GHSA range, so the
			// vulnerable symbols being present does not matter here: the version
			// is fixed. This is the merged-data range win.
			p := dbtest.NewPackage("github.com/aws/aws-sdk-go", "v1.55.8", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{Symbols: s3cryptoSymbols}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
		})

		t.Run("old aws-sdk-go using vulnerable symbols matches the patched GHSA", func(t *testing.T) {
			// inside the GHSA's < 1.34.0 window the merged record matches — but
			// only because this binary uses s3crypto.NewDecryptionClient.
			p := dbtest.NewPackage("github.com/aws/aws-sdk-go", "v1.33.0", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{Symbols: s3cryptoSymbols}).
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
				WithMetadata(pkg.GolangBinMetadata{Symbols: []string{
					"github.com/aws/aws-sdk-go/service/s3.New",
					"github.com/aws/aws-sdk-go/service/s3.(*S3).GetObject",
				}}).
				Build()

			findings := db.Match(t, matcher, p)

			findings.IsEmpty()
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
	})
}
