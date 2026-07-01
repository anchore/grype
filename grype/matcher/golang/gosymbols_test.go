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
		runtimeWholePkg = "GO-2023-1840" // stdlib "runtime", whole-package (no symbols listed)
	)

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

			// server entrypoints are present -> the DoS matches; runtime is whole-package.
			expectMatches(t, findings, httpServerDoS, runtimeWholePkg)
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

			expectMatches(t, findings, httpServerDoS, runtimeWholePkg)
		})
	})
}
