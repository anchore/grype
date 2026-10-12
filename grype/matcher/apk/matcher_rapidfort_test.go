package apk

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// rapidfort-alpine data carries disclosures and fixes, so a search rule redirects the apk matcher's CPE
// search to rapidfort-alpine rows in place of NVD's (see v6.KnownSearchRules). The fixture carries:
//
//	CVE-2024-2398 / curl: rapidfort-alpine:3.18 fix (8.7.1-r0) and an NVD CPE entry (< 8.7.0)
//	CVE-2024-2466 / curl: NVD CPE entry only (>= 8.5.0, < 8.8.0)
//
// On rapidfort-alpine only CVE-2024-2398 surfaces; on plain alpine both do via the CPE search.
func TestRapidFortAlpine_Matching(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortAlpine, "3.18", "")

	dbtest.DBs(t, "rapidfort-alpine").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		t.Run("rapidfort-alpine surfaces only the distro data", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "8.5.0-r0", syftPkg.ApkPkg).
				WithDistro(rfDistro).
				WithCPE("cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.OnlyHasVulnerabilities("CVE-2024-2398")
			findings.SelectMatch("CVE-2024-2398").
				HasOnlyMatchTypes(match.ExactDirectMatch). // no CPE-sourced detail: the upstream search never ran
				HasFix(vulnerability.FixStateFixed, "8.7.1-r0").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		t.Run("plain alpine still reaches the upstream data via the CPE search", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "8.5.0-r0", syftPkg.ApkPkg).
				WithDistro(dbtest.Alpine318).
				WithCPE("cpe:2.3:a:haxx:curl:8.5.0:*:*:*:*:*:*:*").
				Build()

			findings := db.Match(t, &matcher, p)
			findings.ContainsVulnerabilities("CVE-2024-2398", "CVE-2024-2466")
			findings.SkipCompleteness().SelectMatch("CVE-2024-2466").
				SelectDetailByType(match.CPEMatch).
				AsCPESearch()
		})

		t.Run("package at the rapidfort fix version is clean", func(t *testing.T) {
			pkgID := pkg.ID("curl-at-rf-fix")
			p := dbtest.NewPackage("curl", "8.7.1-r0", syftPkg.ApkPkg).
				WithID(pkgID).
				WithDistro(rfDistro).
				WithCPE("cpe:2.3:a:haxx:curl:8.7.1:*:*:*:*:*:*:*").
				Build()

			// the fixed CVE becomes a distro-fixed ownership ignore
			findings := db.Match(t, &matcher, p)
			findings.OnlyHasVulnerabilities()
			findings.Ignores().
				SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CVE-2024-2398").
				ForPackage(pkgID)
		})
	})
}
