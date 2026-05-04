package python

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher_PEP503Normalization covers the canonical-name handling
// from PEP 503 - https://peps.python.org/pep-0503/#normalized-names.
// Python package names are matched after collapsing runs of `-`, `_`,
// and `.` to a single hyphen, so all of the following point at the
// same logical package:
//
//	Django  django  DJANGO
//	oslo.utils  oslo_utils  oslo-utils  Oslo.Utils
//
// The fixture's two GHSAs are stored with the names "Django" and
// "oslo.utils" exactly as upstream publishes them; the matcher must
// resolve any of the equivalent forms above to the stored record. The
// per-column case-insensitive comparison happens in the v6 DB layer;
// the resolver itself only collapses separators.
func TestMatcher_PEP503Normalization(t *testing.T) {
	cases := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		expectGHSAID string
	}{
		{
			name:         "django exact case matches stored Django",
			pkgName:      "Django",
			pkgVersion:   "1.2.5",
			expectGHSAID: "GHSA-h95j-h2rv-qrg4",
		},
		{
			name:         "django lowercase matches stored Django (case-insensitive)",
			pkgName:      "django",
			pkgVersion:   "1.2.5",
			expectGHSAID: "GHSA-h95j-h2rv-qrg4",
		},
		{
			name:         "django uppercase matches stored Django (case-insensitive)",
			pkgName:      "DJANGO",
			pkgVersion:   "1.2.5",
			expectGHSAID: "GHSA-h95j-h2rv-qrg4",
		},
		{
			name:         "oslo.utils dot separator matches stored oslo.utils",
			pkgName:      "oslo.utils",
			pkgVersion:   "0.1.0",
			expectGHSAID: "GHSA-v933-vx5p-j7w2",
		},
		{
			name:         "oslo_utils underscore matches via PEP 503 normalization",
			pkgName:      "oslo_utils",
			pkgVersion:   "0.1.0",
			expectGHSAID: "GHSA-v933-vx5p-j7w2",
		},
		{
			name:         "oslo-utils hyphen matches via PEP 503 normalization",
			pkgName:      "oslo-utils",
			pkgVersion:   "0.1.0",
			expectGHSAID: "GHSA-v933-vx5p-j7w2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dbtest.DBs(t, "python-name-and-vex").
				SelectOnly("github:python/GHSA-h95j-h2rv-qrg4", "github:python/GHSA-v933-vx5p-j7w2").
				Run(func(t *testing.T, db *dbtest.DB) {
					matcher := NewPythonMatcher(MatcherConfig{})
					p := dbtest.NewPackage(c.pkgName, c.pkgVersion, syftPkg.PythonPkg).
						WithLanguage(syftPkg.Python).
						Build()
					db.Match(t, matcher, p).
						SelectMatch(c.expectGHSAID).
						SelectDetailByType(match.ExactDirectMatch).
						AsEcosystemSearch()
				})
		})
	}
}

// TestMatcher_VersionFilteringApplies verifies that PEP 503 name
// matching is paired with proper range filtering: a Django at the fix
// version produces no match.
func TestMatcher_VersionFilteringApplies(t *testing.T) {
	dbtest.DBs(t, "python-name-and-vex").
		SelectOnly("github:python/GHSA-h95j-h2rv-qrg4").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewPythonMatcher(MatcherConfig{})
			// GHSA-h95j-h2rv-qrg4 covers Django <= 1.2.7 and a second
			// entry covering >= 1.3, <= 1.3.1. 1.3.5 is past both.
			p := dbtest.NewPackage("Django", "1.3.5", syftPkg.PythonPkg).
				WithLanguage(syftPkg.Python).
				Build()
			db.Match(t, matcher, p).IsEmpty()
		})
}

// TestMatcher_ChainguardLibrariesSuppressesUpstreamGhsa exercises the
// VEX/unaffected suppression path that the chainguard-libraries
// provider drives. chainguard-libraries publishes annotated-openvex
// statements declaring that specific Chainguard rebuilds (the +cgr.N
// variants) are status=fixed for upstream advisories - the v6
// transformer turns each statement into a UnaffectedPackageHandle
// keyed by the exact rebuilt version, with the upstream advisory IDs
// (CVE / GHSA) as aliases.
//
// The python matcher's findUnaffected query intersects those
// UnaffectedPackageHandle rows with the regular github:python
// disclosures by alias, so a `certifi 2020.12.5+cgr.1` package has the
// upstream GHSA-xqr8-7jwr-rhp7 / CVE-2023-37920 dropped from matches
// and surfaced as ignore filters instead. A vanilla `certifi 2020.12.5`
// (no `+cgr` suffix) does not satisfy the unaffected entry's exact-
// version constraint, so it still gets flagged as vulnerable - this
// is the contrast that proves the VEX statement is what's doing the
// work.
//
// The matcher emits one match.IgnoreRule per alias on the unaffected
// entry: the chainguard advisory itself (CGA-22g9-8qhp-q56g), the
// upstream CVE, and the upstream GHSA - all keyed back to the
// scanned package coordinates so VEX consumers can carry the
// suppression forward.
func TestMatcher_ChainguardLibrariesSuppressesUpstreamGhsa(t *testing.T) {
	const (
		chainguardCGA  = "CGA-22g9-8qhp-q56g"
		upstreamCVE    = "CVE-2023-37920"
		upstreamGHSA   = "GHSA-xqr8-7jwr-rhp7"
		unaffectedRule = "UnaffectedPackageEntry"
	)

	dbtest.DBs(t, "python-name-and-vex").
		SelectOnly(
			"github:python/GHSA-xqr8-7jwr-rhp7",
			"chainguard-libraries:pypi/CGA-22g9-8qhp-q56g",
		).
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewPythonMatcher(MatcherConfig{})

			t.Run("vanilla 2020.12.5 still matches the upstream GHSA", func(t *testing.T) {
				p := dbtest.NewPackage("certifi", "2020.12.5", syftPkg.PythonPkg).
					WithLanguage(syftPkg.Python).
					Build()
				db.Match(t, matcher, p).
					SelectMatch(upstreamGHSA).
					SelectDetailByType(match.ExactDirectMatch).
					AsEcosystemSearch()
			})

			t.Run("chainguard rebuild 2020.12.5+cgr.1 drops the GHSA and emits VEX-style ignore rules", func(t *testing.T) {
				const cgrVersion = "2020.12.5+cgr.1"
				p := dbtest.NewPackage("certifi", cgrVersion, syftPkg.PythonPkg).
					WithLanguage(syftPkg.Python).
					Build()

				findings := db.Match(t, matcher, p)
				ignores := findings.Ignores()
				// the unaffected handle's own ID
				ignores.SelectIgnoreRule(unaffectedRule, chainguardCGA).
					ForPackage("certifi", cgrVersion).
					IncludesAliases()
				// fanned-out alias entries that suppress the upstream IDs
				ignores.SelectIgnoreRule(unaffectedRule, upstreamCVE).
					ForPackage("certifi", cgrVersion).
					IncludesAliases()
				ignores.SelectIgnoreRule(unaffectedRule, upstreamGHSA).
					ForPackage("certifi", cgrVersion).
					IncludesAliases()
			})

			t.Run("certifi past upstream fix is clean - no match, no ignore", func(t *testing.T) {
				// 2023.7.22 is the fixed version per GHSA-xqr8-7jwr-rhp7;
				// no chainguard-libraries entry covers it either, so the
				// package should be vulnerability-free.
				p := dbtest.NewPackage("certifi", "2023.7.22", syftPkg.PythonPkg).
					WithLanguage(syftPkg.Python).
					Build()
				db.Match(t, matcher, p).IsEmpty()
			})
		})
}
