package ruby

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcher_RackVulnerable verifies basic gem matching against a real
// rubygem advisory. The ruby matcher has no resolver, so name matching
// is literal (case-insensitive at the DB layer); the test mainly
// guarantees the matcher path connects an unmodified gem package to a
// github:gem GHSA via the language-ecosystem search.
func TestMatcher_RackVulnerable(t *testing.T) {
	dbtest.DBs(t, "rack").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRubyMatcher(MatcherConfig{})
		// rack < 2.2.19 - 2.2.18 should hit the first range.
		p := dbtest.NewPackage("rack", "2.2.18", syftPkg.GemPkg).
			WithLanguage(syftPkg.Ruby).
			Build()

		db.Match(t, matcher, p).
			SelectMatch("GHSA-wpv5-97wm-hp9c").
			SelectDetailByType(match.ExactDirectMatch).
			AsEcosystemSearch()
	})
}

// TestMatcher_RackFixed verifies that a gem at or past the fix version
// produces no match. Confirms the version-range filter is applied (and
// guards against accidental "any version vulnerable" regressions).
func TestMatcher_RackFixed(t *testing.T) {
	dbtest.DBs(t, "rack").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRubyMatcher(MatcherConfig{})
		// 2.2.19 is the fix; should not match the < 2.2.19 range, and
		// not in the 3.x ranges either.
		p := dbtest.NewPackage("rack", "2.2.19", syftPkg.GemPkg).
			WithLanguage(syftPkg.Ruby).
			Build()
		db.Match(t, matcher, p).IsEmpty()
	})
}
