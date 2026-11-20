package java

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherJava_Lightwell drives Red Hat Lightwell matching for Maven
// packages through a DB that mixes the upstream GHSA disclosure for
// woodstox-core with the three real Lightwell advisories remediating it, one
// per base version line (5.0.3, 6.0.3, 6.2.2).
//
// CVE-2022-40152 / GHSA-3f7h-mf4q-vrm4 flags woodstox-core < 5.4.0 and
// >= 6.0.0 < 6.4.0. Every Lightwell build orders below the upstream fix, so
// the GHSA flags all of them; only the Lightwell advisory for the build's own
// base version line may suppress it.
func TestMatcherJava_Lightwell(t *testing.T) {
	mk := func(version string) pkg.Package {
		return dbtest.NewPackage("woodstox-core", version, syftPkg.JavaPkg).
			WithLanguage(syftPkg.Java).
			WithMetadata(pkg.JavaMetadata{
				PomArtifactID: "woodstox-core",
				PomGroupID:    "com.fasterxml.woodstox",
			}).
			Build()
	}

	const (
		upstreamGHSA   = "GHSA-3f7h-mf4q-vrm4"
		upstreamCVE    = "CVE-2022-40152"
		lightwell603   = "RHLW-2026-403d1e66c95ef9bb"
		unaffectedRule = "UnaffectedPackageEntry"
	)

	dbtest.DBs(t, "lightwell-maven").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewJavaMatcher(MatcherConfig{})

		// Control: the upstream base version is still vulnerable. The 6.0.3
		// advisory's qualifier rejects non-Lightwell builds.
		t.Run("upstream woodstox-core 6.0.3 matches upstream GHSA", func(t *testing.T) {
			db.Match(t, matcher, mk("6.0.3")).
				SelectMatch(upstreamGHSA).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		// Control: upstream past the GHSA range is clean.
		t.Run("upstream woodstox-core 6.4.0 is clean", func(t *testing.T) {
			db.Match(t, matcher, mk("6.4.0")).IsEmpty()
		})

		// NAK suppression: the Lightwell build sits inside the GHSA range, and
		// its own line's advisory removes the GHSA by shared identity.
		t.Run("lightwell 6.0.3.rhlw-00001 at the fix: NAK suppresses", func(t *testing.T) {
			const ver = "6.0.3.rhlw-00001"
			findings := db.Match(t, matcher, mk(ver))
			findings.DoesNotHaveAnyVulnerabilities(upstreamGHSA, upstreamCVE)
			ignores := findings.Ignores()
			ignores.SelectIgnoreRule(unaffectedRule, lightwell603).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
			ignores.SelectIgnoreRule(unaffectedRule, upstreamGHSA).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
			ignores.SelectIgnoreRule(unaffectedRule, upstreamCVE).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
		})

		// A later build on the same line stays covered by the open-ended range.
		t.Run("lightwell 6.0.3.rhlw-00002 above the fix: NAK suppresses", func(t *testing.T) {
			const ver = "6.0.3.rhlw-00002"
			findings := db.Match(t, matcher, mk(ver))
			findings.DoesNotHaveAnyVulnerabilities(upstreamGHSA, upstreamCVE)
			ignores := findings.Ignores()
			ignores.SelectIgnoreRule(unaffectedRule, lightwell603).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
			ignores.SelectIgnoreRule(unaffectedRule, upstreamGHSA).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
			ignores.SelectIgnoreRule(unaffectedRule, upstreamCVE).
				ForPackage("woodstox-core", ver).
				IncludesAliases()
		})

		// Below the fix on its own line: the 6.2.2 line's fix is rhlw-00004.
		t.Run("lightwell 6.2.2.rhlw-00003 below its line's fix: GHSA matches", func(t *testing.T) {
			db.Match(t, matcher, mk("6.2.2.rhlw-00003")).
				SelectMatch(upstreamGHSA).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		// Cross-line isolation: a Lightwell build on a line without an
		// advisory orders above the 5.0.3 and 6.0.3 fixes, but neither of
		// those advisories may clear it.
		t.Run("lightwell 6.1.0.rhlw-00001 on an unremediated line: GHSA matches", func(t *testing.T) {
			db.Match(t, matcher, mk("6.1.0.rhlw-00001")).
				SelectMatch(upstreamGHSA).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})
	})
}
