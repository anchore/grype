package javascript

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherJavaScript_RootIO drives rootio matching for npm packages
// through a DB that mixes rootio NAK records and the matching GHSA
// disclosures keyed under the bare npm name.
//
// Two real-world packages cover the scenarios:
//   - json-schema (CVE-2021-3918 / GHSA-896r-f27r-55mw): GHSA flags any
//     version < 0.4.0 as vulnerable; rootio backports a fix at
//     0.2.3-root.io.1. Below the rootio fix the bare-name fanout finds
//     the GHSA disclosure; at the rootio fix the NAK suppresses it.
//   - http-cache-semantics (CVE-2022-25881 / GHSA-rc47-6667-2j5j): GHSA
//     range < 4.1.1; rootio fix at 3.8.1-root.io.1.
//
// Rootio's npm packages live under the @rootio/ scope. StripPrefix maps
// `@rootio/json-schema` → `json-schema` so the language matcher finds
// the upstream disclosure keyed under the bare name.
func TestMatcherJavaScript_RootIO(t *testing.T) {
	tests := []struct {
		name              string
		pkgName           string
		pkgVersion        string
		expectGHSA        string     // primary match ID; empty means no match
		expectType        match.Type // ignored when expectGHSA is empty
		expectSuppressIDs []string   // IgnoreRule IDs the NAK fans out to
	}{
		{
			// @rootio/json-schema: rootio fix 0.2.3-root.io.1. At 0.2.2 the
			// package is below the rootio backport, and GHSA flags
			// json-schema < 0.4.0 — so the bare-name fanout surfaces the
			// upstream GHSA disclosure.
			name:       "@rootio/json-schema below rootio fix: GHSA flags it",
			pkgName:    "@rootio/json-schema",
			pkgVersion: "0.2.2",
			expectGHSA: "GHSA-896r-f27r-55mw",
			expectType: match.ExactDirectMatch,
		},
		{
			// At the rootio fix, the NAK suppresses the GHSA. Note that
			// 0.2.3-root.io.1 is still < 0.4.0 per semver pre-release
			// ordering, so the disclosure would land on the scan without
			// the NAK in place.
			name:       "@rootio/json-schema at rootio fix: NAK suppresses",
			pkgName:    "@rootio/json-schema",
			pkgVersion: "0.2.3-root.io.1",
			expectSuppressIDs: []string{
				"ROOT-APP-NPM-CVE-2021-3918",
				"CVE-2021-3918",
			},
		},
		{
			name:       "@rootio/http-cache-semantics below rootio fix: GHSA flags it",
			pkgName:    "@rootio/http-cache-semantics",
			pkgVersion: "3.8.0",
			expectGHSA: "GHSA-rc47-6667-2j5j",
			expectType: match.ExactDirectMatch,
		},
		{
			name:       "@rootio/http-cache-semantics at rootio fix: NAK suppresses",
			pkgName:    "@rootio/http-cache-semantics",
			pkgVersion: "3.8.1-root.io.1",
			expectSuppressIDs: []string{
				"ROOT-APP-NPM-CVE-2022-25881",
				"CVE-2022-25881",
			},
		},
		{
			// A regular (non-rootio) http-cache-semantics package at a
			// vulnerable version matches the GHSA directly.
			name:       "regular http-cache-semantics vulnerable: direct GHSA match",
			pkgName:    "http-cache-semantics",
			pkgVersion: "3.8.0",
			expectGHSA: "GHSA-rc47-6667-2j5j",
			expectType: match.ExactDirectMatch,
		},
		{
			// Past the GHSA fix range, the regular package is clean and
			// the rootio NAK (keyed under @rootio/) stays out of reach.
			name:       "regular http-cache-semantics past upstream fix: no match",
			pkgName:    "http-cache-semantics",
			pkgVersion: "4.1.1",
		},
		{
			// Unrelated package gets nothing.
			name:       "unrelated package: nothing",
			pkgName:    "lodash",
			pkgVersion: "4.17.21",
		},
	}

	dbtest.DBs(t, "rootio-npm").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewJavascriptMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.NpmPkg).
					WithLanguage(syftPkg.JavaScript).
					Build()

				findings := db.Match(t, matcher, p)

				if tt.expectGHSA == "" && len(tt.expectSuppressIDs) == 0 {
					findings.IsEmpty()
					return
				}

				if tt.expectGHSA != "" {
					findings.SelectMatch(tt.expectGHSA).
						SelectDetailByType(tt.expectType).
						AsEcosystemSearch()
				}

				if len(tt.expectSuppressIDs) > 0 {
					ignores := findings.Ignores()
					for _, id := range tt.expectSuppressIDs {
						ignores.SelectIgnoreRule("UnaffectedPackageEntry", id).
							ForPackage(tt.pkgName, tt.pkgVersion).
							IncludesAliases()
					}
				}
			})
		}
	})
}
