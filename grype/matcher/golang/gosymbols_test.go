package golang

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherGolang_GoSymbols exercises the gosymbols qualifier end to end using
// real, compiled Go binaries. Each fixture under testdata/gobin-* is built and
// scanned through grype's production package provider with Go symbol capture
// enabled (the same path `grype ./some-binary` takes), so the packages carry the
// exact function symbols grype sees in the field — not hand-written lists.
//
// Matching runs against the govulndb-go DB fixture. Its GO-2022-0969 record
// carries the vulnerable net/http (stdlib) and golang.org/x/net/http2 server
// symbols via ecosystem_specific.imports, which the govulndb transformer lands
// as the go-imports qualifier. GO-2023-1840 lists the whole "runtime" package
// (no symbols), which every Go binary satisfies.
//
// The headline behavior: a binary that only *links* net/http or golang.org/x/net
// without using the vulnerable server symbols no longer matches GO-2022-0969 —
// eliminating the false positive that module-granularity matching produced —
// while a binary that does use those symbols still matches.
func TestMatcherGolang_GoSymbols(t *testing.T) {
	const (
		httpServerDoS   = "GO-2022-0969" // net/http (stdlib) & golang.org/x/net/http2 server DoS; symbol-scoped
		runtimeWholePkg = "GO-2023-1840" // stdlib "runtime", whole-package (no symbols listed); CVE-2023-29403
	)

	// the "toolchain" pseudo-module records from the same Go release train as GO-2023-1840:
	// cmd/go and cgo flaws (CVE-2023-29402/29404/29405) that live on the build machine and are
	// never compiled into an artifact. See the anchore/grype#1782 scenario below.
	toolchainRecords := []string{"GO-2023-1839", "GO-2023-1841", "GO-2023-1842"}

	// go1.18.0 sits in GO-2022-0969's first vulnerable window (< 1.18.6) and below
	// GO-2023-1840's fix (< 1.19.10), so a stdlib package at this version is a
	// candidate for both; only the captured symbols decide whether GO-2022-0969
	// survives. The real toolchain-baked stdlib version (e.g. go1.26.0) is past
	// every window, so version is set explicitly here while the symbols stay real.
	const vulnerableStdlibVersion = "go1.18.0"

	// a golang.org/x/net pseudo-version older than GO-2022-0969's fix
	// (0.0.0-20220906165146-f3363e06e74c). This matches the version the x/net
	// fixtures are actually built against.
	const vulnerableXNetVersion = "v0.0.0-20220225172249-27dd8689420f"

	dbtest.DBs(t, "govulndb-go").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewGolangMatcher(MatcherConfig{})

		expectMatches := func(t *testing.T, f *dbtest.FindingsAssertion, ids ...string) {
			t.Helper()
			for _, id := range ids {
				f.SelectMatch(id).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
			}
		}

		t.Run("stdlib server binary uses vulnerable net/http server symbols -> GO-2022-0969 matches", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-httpserver").
				Package("stdlib").
				WithVersion(vulnerableStdlibVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// server entrypoints are present -> the DoS matches; the specific matched
			// net/http symbols vary with the compiled toolchain, so only their presence
			// is asserted here. runtime is a whole-package (symbol-less) advisory import,
			// so its matched-symbols value is the import path alone, deterministically.
			findings.SelectMatch(httpServerDoS).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch()
			findings.SelectMatch(runtimeWholePkg).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch().
				HasMatchedSymbols("runtime")
		})

		t.Run("stdlib client-only binary lacks server symbols -> GO-2022-0969 suppressed", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-httpclient").
				Package("stdlib").
				WithVersion(vulnerableStdlibVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// this binary links net/http (client calls) but uses none of the vulnerable
			// server symbols, so the DoS is filtered out - the false positive is gone.
			findings.DoesNotHaveAnyVulnerabilities(httpServerDoS)
			// it still links runtime, so the whole-package runtime advisory correctly matches.
			expectMatches(t, findings, runtimeWholePkg)
		})

		t.Run("x/net http2 server binary uses vulnerable symbols -> GO-2022-0969 matches", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-xnet-http2server").
				Package("golang.org/x/net").
				WithVersion(vulnerableXNetVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// http2.(*Server).ServeConn is present -> the x/net advisory matches.
			expectMatches(t, findings, httpServerDoS)
		})

		t.Run("x/net html-only binary lacks http2 server symbols -> GO-2022-0969 suppressed", func(t *testing.T) {
			p := dbtest.GoBinaryFixture(t, "gobin-xnet-html").
				Package("golang.org/x/net").
				WithVersion(vulnerableXNetVersion).
				Build()

			findings := db.Match(t, matcher, p)

			// links golang.org/x/net at a vulnerable version but uses only html, not the
			// vulnerable http2 server symbols, so there is no match at all (GO-2022-0969 is
			// the only x/net advisory in the fixture).
			findings.IsEmpty()
		})

		t.Run("stdlib binary without captured symbols falls back to module matching", func(t *testing.T) {
			// mirrors an SBOM produced without symbol capture (syft's default), e.g.
			// `syft ... | grype`: with no symbol evidence the qualifier is satisfied and
			// matching stays at module granularity, preserving pre-feature behavior.
			p := dbtest.NewPackage("stdlib", vulnerableStdlibVersion, syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{}).
				Build()

			findings := db.Match(t, matcher, p)

			// no symbol evidence -> matching stays at module granularity and no
			// intersection is reported, so matchedSymbols is empty on every match.
			findings.SelectMatch(httpServerDoS).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch().
				HasMatchedSymbols("")
			findings.SelectMatch(runtimeWholePkg).SelectDetailByType(match.ExactDirectMatch).AsEcosystemSearch().
				HasMatchedSymbols("")
		})

		t.Run("build-time toolchain advisories never match a compiled binary (anchore/grype#1782)", func(t *testing.T) {
			// The anchore/grype#1782 reproduction: a binary-only image (calico
			// kube-controllers, built with go1.15.2) was flagged with CVE-2023-29402/29404/
			// 29405 — cmd/go and cgo flaws that affect the machine that RAN the build, not
			// the artifact it produced — when only CVE-2023-29403 (GO-2023-1840, a flaw in
			// the runtime package that IS compiled into every binary) should apply.
			//
			// Two mechanisms produce the issue's expected output. Build-time vs runtime:
			// govulndb models toolchain flaws as the "toolchain" pseudo-module
			// (GO-2023-1839/1841/1842 here), and a scanned binary catalogs its Go version
			// as "stdlib" — never "toolchain" — so under exact-name matching the toolchain
			// records cannot reach it, even though go1.15.2 sits squarely inside their
			// vulnerable ranges. (The NVD CPE route to the same false positives was closed
			// separately by disabling stdlib CPE matching by default, #3517.) Symbol
			// filtering: the same binary links net/http without the vulnerable server
			// symbols, so GO-2022-0969 is suppressed too. What remains is exactly what the
			// issue reporter said should remain: GO-2023-1840, whose whole-package
			// "runtime" import every Go binary satisfies.
			p := dbtest.NewPackage("stdlib", "go1.15.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{Symbols: []string{
					"runtime.main",
					"runtime.gcBgMarkWorker",
					"net/http.Get",
					"net/http.(*Client).Do",
				}}).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, runtimeWholePkg)
			findings.DoesNotHaveAnyVulnerabilities(append([]string{httpServerDoS}, toolchainRecords...)...)
		})

		t.Run("toolchain records exist in the DB and only a toolchain-named package can match them", func(t *testing.T) {
			// pins the other half of the #1782 contract: the toolchain records are written
			// (a scan of a Go SDK installation is their legitimate consumer), and the only
			// thing that can ever match them is a package literally named "toolchain" —
			// which binary scans never produce (syft catalogs the embedded Go version as
			// "stdlib"). If this match ever disappears, the records were silently dropped;
			// if the scenario above ever matched them, the name-based separation broke.
			p := dbtest.NewPackage("toolchain", "go1.15.2", syftPkg.GoModulePkg).
				WithLanguage(syftPkg.Go).
				WithMetadata(pkg.GolangBinMetadata{}).
				Build()

			findings := db.Match(t, matcher, p)

			expectMatches(t, findings, toolchainRecords...)
		})
	})
}
