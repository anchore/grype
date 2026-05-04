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
			dbtest.DBs(t, "django-and-oslo").Run(func(t *testing.T, db *dbtest.DB) {
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
	dbtest.DBs(t, "django-and-oslo").
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
