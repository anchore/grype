package java

import (
	"testing"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// === CPE match details for Java packages (match.java.using-cpes: true) ===
//
// Java is a good lens on the shared CPE path in matcher/internal: it reaches it
// through MatchPackageByEcosystemAndCPEs, exactly like javascript, python, ruby,
// dotnet, rust, hex, golang and stock do, so whatever these tests observe about
// CPE match details holds for every CPE-enabled matcher.
//
// The nvd-cpe-details fixture holds two synthetic NVD records:
//
//   - CVE-2026-40001 lists two distinct vulnerable CPEs for one CVE:
//     acme:widget       >= 1.0.0 < 2.0.0  (fixed in 2.0.0)
//     acme:widget-core  >= 1.0.0 < 3.0.0  (fixed in 3.0.0)
//     NVD stores one affected-CPE record per vulnerable CPE, so a package that
//     matches both ends up with two records under one CVE ID that differ only
//     by constraint and fix version. This is common in real NVD data.
//
//   - CVE-2026-40002 lists a single vulnerable CPE (acme:gadget), used to
//     observe how the searched-by CPE is rendered when the package version
//     carries WFN punctuation.
func TestMatcherJava_CPEMatchDetails(t *testing.T) {
	dbtest.DBs(t, "nvd-cpe-details").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewJavaMatcher(MatcherConfig{UseCPEs: true})

		// One CVE reached through two of the package's CPEs, where each CPE
		// resolves to a separate DB record with its own constraint and fix.
		//
		// One CVE on one package is one finding, however many records produced
		// it: a match.Fingerprint is exactly (vulnerability, package), so
		// Set.ToMatches groups the records under one fingerprint and folds them
		// together with match.Match.Merge -- fix versions unioned, both records'
		// details kept. Keying the fingerprint on the fix version as well (as it
		// once did) would report this CVE twice for one package.
		t.Run("one CVE via two CPEs with differing fixes", func(t *testing.T) {
			p := dbtest.NewPackage("widget-core", "1.5.0", syftPkg.JavaPkg).
				WithLanguage(syftPkg.Java).
				WithMetadata(pkg.JavaMetadata{
					PomArtifactID: "widget-core",
					PomGroupID:    "com.acme",
				}).
				WithCPE("cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*").
				WithCPE("cpe:2.3:a:acme:widget-core:1.5.0:*:*:*:*:*:*:*").
				Build()

			// a single finding, fixed by either record's version...
			finding := db.Match(t, matcher, p).
				SelectMatch("CVE-2026-40001")
			finding.HasFix(vulnerability.FixStateFixed, "2.0.0", "3.0.0").
				HasDetailCount(2)

			// ...carrying a detail per record, each describing its own record
			finding.SelectDetailByCPE("cpe:2.3:a:acme:widget:1.5.0:*:*:*:*:*:*:*", ">= 1.0.0, < 2.0.0 (unknown)").
				FoundCPEs("cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*")
			finding.SelectDetailByCPE("cpe:2.3:a:acme:widget-core:1.5.0:*:*:*:*:*:*:*", ">= 1.0.0, < 3.0.0 (unknown)").
				FoundCPEs("cpe:2.3:a:acme:widget-core:*:*:*:*:*:*:*:*")
		})

		// The same shape as the one above, but reached through a *single* package CPE, and with one
		// of the two records unfixed. The fix state has to survive the merge: a record that reports
		// no fix must not mask the fix the other record does report.
		//
		// Modeled on real NVD data. CVE-2017-9229 lists cpe:2.3:a:php:php twice: once unqualified
		// (>= 5.6.0, < 5.6.31 || >= 7.0.0, < 7.0.21 || >= 7.1.0, < 7.1.7, fixed) and once for
		// target software "oniguruma-mod" (<= 7.1.5, no fix). A php 7.1.5 CPE matches both, and
		// grype reported CVE-2017-9229 twice for one php package. To see it against a real DB:
		//
		//	grype 'pkg:generic/php@7.1.5' --add-cpes-if-none -o json
		//
		// CVE-2026-40003 mirrors that: acme:gizmo unqualified (>= 1.0.0, < 2.0.0, fixed in 2.0.0) and
		// acme:gizmo for target software "embedded-mod" (<= 1.5.0, no fix).
		t.Run("one CPE matching a fixed and an unfixed record", func(t *testing.T) {
			p := dbtest.NewPackage("gizmo", "1.5.0", syftPkg.JavaPkg).
				WithLanguage(syftPkg.Java).
				WithMetadata(pkg.JavaMetadata{
					PomArtifactID: "gizmo",
					PomGroupID:    "com.acme",
				}).
				WithCPE("cpe:2.3:a:acme:gizmo:1.5.0:*:*:*:*:*:*:*").
				Build()

			// one finding, still reporting the fix the unqualified record provides
			finding := db.Match(t, matcher, p).
				SelectMatch("CVE-2026-40003")
			finding.HasFix(vulnerability.FixStateFixed, "2.0.0").
				HasDetailCount(2)

			// both records searched by the same package CPE, each detail describing its own record
			finding.SelectDetailByCPE("cpe:2.3:a:acme:gizmo:1.5.0:*:*:*:*:*:*:*", ">= 1.0.0, < 2.0.0 (unknown)").
				FoundCPEs("cpe:2.3:a:acme:gizmo:*:*:*:*:*:*:*:*")
			finding.SelectDetailByCPE("cpe:2.3:a:acme:gizmo:1.5.0:*:*:*:*:*:*:*", "<= 1.5.0 (unknown)").
				FoundCPEs("cpe:2.3:a:acme:gizmo:*:*:*:*:*:embedded-mod:*:*")
		})

		// A package version containing WFN punctuation ("+" in a build suffix).
		//
		// The searched-by CPE must be WFN-escaped, i.e. rendered with
		// cpe.Attributes.String() rather than BindToFmtString() (which leaves
		// punctuation unquoted). That is the form the rest of grype emits,
		// including the found CPEs on this very detail.
		t.Run("searched-by CPE rendering when the version has WFN punctuation", func(t *testing.T) {
			p := dbtest.NewPackage("gadget", "1.5.0+build.7", syftPkg.JavaPkg).
				WithLanguage(syftPkg.Java).
				WithMetadata(pkg.JavaMetadata{
					PomArtifactID: "gadget",
					PomGroupID:    "com.acme",
				}).
				WithCPE(`cpe:2.3:a:acme:gadget:1.5.0\+build.7:*:*:*:*:*:*:*`).
				Build()

			db.Match(t, matcher, p).
				SelectMatch("CVE-2026-40002").
				HasDetailCount(1).
				SelectDetailByCPE(`cpe:2.3:a:acme:gadget:1.5.0\+build.7:*:*:*:*:*:*:*`, ">= 1.0.0, < 2.0.0 (unknown)").
				FoundCPEs("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*")
		})

		// Control: a version-specific CPE in the DB record is unaffected by the
		// found-CPE version filtering that moved into result.provider — v6
		// always stores a vulnerability's CPEs with version=ANY, so both the old
		// filterCPEsByVersion and the new matchedCPEsForSearch are no-ops here.
		t.Run("found CPEs are the record's CPEs, version-agnostic", func(t *testing.T) {
			p := dbtest.NewPackage("gadget", "1.9.9", syftPkg.JavaPkg).
				WithLanguage(syftPkg.Java).
				WithMetadata(pkg.JavaMetadata{
					PomArtifactID: "gadget",
					PomGroupID:    "com.acme",
				}).
				WithCPE("cpe:2.3:a:acme:gadget:1.9.9:*:*:*:*:*:*:*").
				Build()

			db.Match(t, matcher, p).
				SelectMatch("CVE-2026-40002").
				SelectDetailByCPE("cpe:2.3:a:acme:gadget:1.9.9:*:*:*:*:*:*:*").
				FoundCPEs("cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*")
		})
	})
}
