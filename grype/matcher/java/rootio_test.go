package java

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// TestMatcherJava_RootIO drives rootio matching for Maven packages through
// a DB that mixes a rootio NAK record (keyed under
// `io.root.org.springframework:spring-core`) and the matching GHSA
// disclosure (keyed under `org.springframework:spring-core`).
//
// Realistic Syft shape is critical here: Syft puts the artifactID alone in
// p.Name (e.g. `spring-core`) and the Maven groupID in
// JavaMetadata.PomGroupID. The rootio brand on a Java package is a groupID
// prefix, so detection has to consult the metadata — checking p.Name alone
// misses real rootio Java packages entirely.
//
// CVE-2025-41249 / GHSA-jmp9-x22r-554x flags spring-core in range
// >= 5.3.0 <= 5.3.44. Rootio backports the fix at 5.3.40-root.io.1.
func TestMatcherJava_RootIO(t *testing.T) {
	mk := func(groupID, version string) pkg.Package {
		return dbtest.NewPackage("spring-core", version, syftPkg.JavaPkg).
			WithLanguage(syftPkg.Java).
			WithMetadata(pkg.JavaMetadata{
				PomArtifactID: "spring-core",
				PomGroupID:    groupID,
			}).
			Build()
	}

	const (
		upstreamGHSA   = "GHSA-jmp9-x22r-554x"
		upstreamCVE    = "CVE-2025-41249"
		rootioID       = "ROOT-APP-MAVEN-CVE-2025-41249"
		unaffectedRule = "UnaffectedPackageEntry"
	)

	dbtest.DBs(t, "rootio-maven").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewJavaMatcher(MatcherConfig{})

		// Control: vanilla upstream Spring at a vulnerable version matches the
		// GHSA directly. No fanout, no rootio detection — just the existing
		// Java matcher path.
		t.Run("vanilla spring-core 5.3.39 matches upstream GHSA", func(t *testing.T) {
			db.Match(t, matcher, mk("org.springframework", "5.3.39")).
				SelectMatch(upstreamGHSA).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		// Control: vanilla upstream past the GHSA range is clean.
		t.Run("vanilla spring-core 5.3.45 is clean", func(t *testing.T) {
			db.Match(t, matcher, mk("org.springframework", "5.3.45")).IsEmpty()
		})

		// Rootio detection + fanout: a rootio Java pkg below the rootio fix
		// still matches the upstream GHSA. The match only emerges if the
		// matcher (a) detects rootio from PomGroupID, (b) fans out the search
		// to the bare `org.springframework:spring-core` name, and (c) finds
		// the GHSA keyed under that bare name.
		t.Run("rootio spring-core 5.3.39 below rootio fix: GHSA via fanout", func(t *testing.T) {
			db.Match(t, matcher, mk("io.root.org.springframework", "5.3.39")).
				SelectMatch(upstreamGHSA).
				SelectDetailByType(match.ExactDirectMatch).
				AsEcosystemSearch()
		})

		// NAK suppression: the rootio Java pkg at the rootio fix version is
		// inside the upstream GHSA range, so the GHSA alone can't clear it —
		// the rootio NAK has to suppress via cross-name Remove.
		t.Run("rootio spring-core 5.3.40-root.io.1 at rootio fix: NAK suppresses", func(t *testing.T) {
			const ver = "5.3.40-root.io.1"
			findings := db.Match(t, matcher, mk("io.root.org.springframework", ver))
			ignores := findings.Ignores()
			ignores.SelectIgnoreRule(unaffectedRule, rootioID).
				ForPackage("spring-core", ver).
				IncludesAliases()
			ignores.SelectIgnoreRule(unaffectedRule, upstreamCVE).
				ForPackage("spring-core", ver).
				IncludesAliases()
		})

		// Cross-name isolation: a rootio Java pkg on an unrelated artifact
		// shouldn't pick up the spring-core NAK.
		t.Run("rootio unrelated artifact: nothing", func(t *testing.T) {
			db.Match(t, matcher, mk("io.root.org.springframework", "5.0.0")).
				IsEmpty() // 5.0.0 is below GHSA range >= 5.3.0
		})
	})
}
