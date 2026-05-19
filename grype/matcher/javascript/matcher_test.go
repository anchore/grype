package javascript

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher_ScopedAndUnscopedNames covers npm's package-name
// namespacing - scoped names like "@babel/traverse" vs the legacy
// unscoped form "babel-traverse". GHSA-67hx-6x53-jw92 (CVE-2023-45133)
// is one of the rare advisories that lists both forms as separate
// FixedIn entries, so a single fixture exercises:
//
//   - the scoped name path (no resolver normalization for npm; the
//     literal package name must equal the stored DB name)
//   - the legacy unscoped form
//   - the false-positive guard: a bare "traverse" package that is
//     neither scoped nor the legacy alias must NOT match either entry
//
// Past bugs in this area have come from accidentally treating "traverse"
// as equivalent to "@babel/traverse" or stripping the "@scope/" prefix.
func TestMatcher_ScopedAndUnscopedNames(t *testing.T) {
	cases := []struct {
		name        string
		pkgName     string
		expectMatch bool
	}{
		{
			name:        "scoped name matches the scoped GHSA entry",
			pkgName:     "@babel/traverse",
			expectMatch: true,
		},
		{
			name:        "legacy unscoped name matches the unscoped GHSA entry",
			pkgName:     "babel-traverse",
			expectMatch: true,
		},
		{
			name:        "bare name does not collide with either GHSA entry",
			pkgName:     "traverse",
			expectMatch: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbtest.DBs(t, "npm-scope-handling").
				SelectOnly("github:npm/GHSA-67hx-6x53-jw92").
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewJavascriptMatcher(MatcherConfig{})
					p := dbtest.NewPackage(c.pkgName, "7.20.0", syftPkg.NpmPkg).
						WithLanguage(syftPkg.JavaScript).
						Build()

					findings := db.Match(t, matcher, p)
					if c.expectMatch {
						findings.SelectMatch("GHSA-67hx-6x53-jw92").
							SelectDetailByType(match.ExactDirectMatch).
							AsEcosystemSearch()
					} else {
						findings.IsEmpty()
					}
				})
		})
	}
}

// TestMatcher_ScopeStreamsDoNotCross is the sharp version of the
// scope-handling test: two distinct, real GHSAs - one affecting only
// the scoped form, one affecting only the unscoped form, with the
// scoped form's suffix exactly equal to the unscoped form's name.
//
//   - GHSA-rmvr-2pp2-xj38 (CVE-2025-25290) affects only @octokit/request
//   - GHSA-7xfp-9c55-5vqj (CVE-2017-16026) affects only "request"
//
// A buggy matcher that strips "@scope/" or treats the suffix as
// equivalent to a bare package name would cross-emit the wrong GHSA
// against the wrong package. This test fails such regressions:
//
//   - @octokit/request must hit GHSA-rmvr-... and *not* GHSA-7xfp-...
//   - request must hit GHSA-7xfp-... and *not* GHSA-rmvr-...
func TestMatcher_ScopeStreamsDoNotCross(t *testing.T) {
	cases := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		expectGHSAID string
		forbidGHSAID string
	}{
		{
			name:         "@octokit/request only matches its own scoped GHSA",
			pkgName:      "@octokit/request",
			pkgVersion:   "9.0.0", // in [9.0.0-beta.1, 9.2.1)
			expectGHSAID: "GHSA-rmvr-2pp2-xj38",
			forbidGHSAID: "GHSA-7xfp-9c55-5vqj",
		},
		{
			name:         "unscoped request only matches its own unscoped GHSA",
			pkgName:      "request",
			pkgVersion:   "2.50.0", // in [2.49.0, 2.68.0)
			expectGHSAID: "GHSA-7xfp-9c55-5vqj",
			forbidGHSAID: "GHSA-rmvr-2pp2-xj38",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbtest.DBs(t, "npm-scope-handling").
				SelectOnly(
					"github:npm/GHSA-rmvr-2pp2-xj38",
					"github:npm/GHSA-7xfp-9c55-5vqj",
				).
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewJavascriptMatcher(MatcherConfig{})
					p := dbtest.NewPackage(c.pkgName, c.pkgVersion, syftPkg.NpmPkg).
						WithLanguage(syftPkg.JavaScript).
						Build()

					findings := db.Match(t, matcher, p)
					findings.DoesNotHaveAnyVulnerabilities(c.forbidGHSAID)
					findings.SelectMatch(c.expectGHSAID).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				})
		})
	}
}

// TestMatcher_VersionFilteringForScopedPackage verifies that the
// version filter still applies on the scoped path: a @babel/traverse
// past the fix (7.23.2) must produce no match even though the package
// name matches a stored GHSA entry.
func TestMatcher_VersionFilteringForScopedPackage(t *testing.T) {
	dbtest.DBs(t, "npm-scope-handling").
		SelectOnly("github:npm/GHSA-67hx-6x53-jw92").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewJavascriptMatcher(MatcherConfig{})
			// fix is 7.23.2; the package is at 7.23.5, past the fix.
			p := dbtest.NewPackage("@babel/traverse", "7.23.5", syftPkg.NpmPkg).
				WithLanguage(syftPkg.JavaScript).
				Build()
			db.Match(t, matcher, p).IsEmpty()
		})
}
