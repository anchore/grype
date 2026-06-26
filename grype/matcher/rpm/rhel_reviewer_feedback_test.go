package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// These cases come from an expert reviewer's findings on two real images:
//   - a python 3.12 image (RHEL 9.4)
//   - an OSE console image (RHEL 9.2)
// Each uses the actual installed package version from that image's SBOM and the real
// vunnel record (OSE records include the AdditionalAdvisoryFixes vunnel should emit). They
// assert the reviewer's expected-correct outcome, so any that fail mark behavior we have not
// fixed yet.

// rhelIndirectRPMHost models a binary RPM whose source RPM differs (e.g. libcurl-minimal built
// from the curl source RPM), engaging the matcher's source-indirection path that the RHEL data
// (keyed on the source RPM) requires.
func rhelIndirectRPMHost(binary, source string, d *distro.Distro, epoch int, version string, id pkg.ID) pkg.Package {
	return dbtest.NewPackage(binary, version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithUpstream(source, version).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(epoch)}).
		Build()
}

// --- python 3.12 image, RHEL 9.4 ---

func TestReviewerFeedback_PythonImage(t *testing.T) {
	dbtest.DBs(t, "rhel-reviewer-feedback").
		SelectOnly("rhel:9/cve-2023-25433", "rhel:9/cve-2021-20197", "rhel:9/cve-2025-59464", "rhel:9/cve-2026-2100").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel94 := distro.New(distro.RedHat, "9.4", "")

			// CVE-2023-25433 (libtiff) - Red Hat lists RHEL 9 as affected, no fix yet: must be reported.
			t.Run("libtiff affected/no-fix is reported", func(t *testing.T) {
				p := rhelDirectRPMHost("libtiff", rhel94, 0, "0:4.4.0-12.el9", pkg.ID("libtiff")).Build()
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2023-25433").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			// CVE-2021-20197 (binutils) - same: affected on RHEL 9, no fix.
			t.Run("binutils affected/no-fix is reported", func(t *testing.T) {
				p := rhelDirectRPMHost("binutils", rhel94, 0, "0:2.35.2-43.el9", pkg.ID("binutils")).Build()
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2021-20197").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			// CVE-2025-59464 (nodejs:20) - marked will-not-fix: reported with a wont-fix state.
			t.Run("nodejs:20 wont-fix is reported as wont-fix", func(t *testing.T) {
				p := dbtest.NewPackage("nodejs", "1:20.16.0-1.module+el9.4.0+22197+9e60f127", syftPkg.RpmPkg).
					WithID(pkg.ID("nodejs")).
					WithDistro(rhel94).
					WithMetadata(pkg.RpmMetadata{
						Epoch:           intPtr(1),
						ModularityLabel: strPtr("nodejs:20:9040020240807145403:rhel9"),
					}).
					Build()
				db.Match(t, &Matcher{}, p).
					SelectMatch("CVE-2025-59464").
					HasFix(vulnerability.FixStateWontFix).
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})

			// CVE-2026-2100 (p11-kit) - affected per RHSA-2026:18599, fixed in 0:0.26.2-1.el9.
			t.Run("p11-kit below the fix is reported", func(t *testing.T) {
				p := rhelDirectRPMHost("p11-kit", rhel94, 0, "0:0.25.3-2.el9", pkg.ID("p11-kit")).Build()
				sf := db.Match(t, &Matcher{}, p).SelectMatch("CVE-2026-2100")
				sf.HasFix(vulnerability.FixStateFixed, "0:0.26.2-1.el9")
				sf.SelectDetailByType(match.ExactDirectMatch).AsDistroSearch()
			})
		})
}

// --- OSE console image, RHEL 9.2 ---
//
// Each package below carries the fix for its 9.2 stream (its .el9_2.N release is at or past the
// 9.2 RHSA's build) but sits below the later 9.3 build that vunnel collapses to as the canonical
// fix. The reviewer's point ("not picking up both advisories") is that grype only knows the 9.3
// advisory and therefore false-positives the patched 9.2 host. Correct outcome: not vulnerable.

func TestReviewerFeedback_OSEImage(t *testing.T) {
	dbtest.DBs(t, "rhel-reviewer-feedback").
		SelectOnly("rhel:9/cve-2023-4813", "rhel:9/cve-2023-4806", "rhel:9/cve-2023-38545", "rhel:9/cve-2023-38546", "rhel:9/cve-2023-44487").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel92 := distro.New(distro.RedHat, "9.2", "")

			// glibc 2.34-60.el9_2.14 carries the 9.2 fix (RHSA-2023:5453 shipped -60.el9_2.7).
			for _, cve := range []string{"CVE-2023-4813", "CVE-2023-4806"} {
				t.Run("glibc patched on 9.2 stream not flagged: "+cve, func(t *testing.T) {
					p := rhelDirectRPMHost("glibc", rhel92, 0, "0:2.34-60.el9_2.14", pkg.ID("glibc-"+cve)).Build()
					// glibc's two CVEs are loaded together and both suppress on the 9.2 stream, so
					// the sibling CVE also produces an ignore; scope this subtest to the one CVE.
					db.Match(t, &Matcher{}, p).
						Ignores().
						SkipCompleteness().
						SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, cve)
				})
			}

			// libcurl-minimal 7.76.1-23.el9_2.7 carries the 9.2 fix (RHSA-2023:5763 shipped -23.el9_2.4).
			for _, cve := range []string{"CVE-2023-38545", "CVE-2023-38546"} {
				t.Run("curl patched on 9.2 stream not flagged: "+cve, func(t *testing.T) {
					pkgID := pkg.ID("libcurl-minimal-" + cve)
					p := rhelIndirectRPMHost("libcurl-minimal", "curl", rhel92, 0, "0:7.76.1-23.el9_2.7", pkgID)
					// curl's two CVEs are loaded together and both suppress on the 9.2 stream, so the
					// sibling CVE also produces an ignore; scope this subtest to the one CVE.
					db.Match(t, &Matcher{}, p).
						Ignores().
						SkipCompleteness().
						SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, cve).
						ForPackage(pkgID).
						WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
				})
			}

			// libnghttp2 1.43.0-5.el9_2.3 carries the 9.2 fix (RHSA-2023:5838 shipped -5.el9_2.1).
			t.Run("nghttp2 patched on 9.2 stream not flagged: CVE-2023-44487", func(t *testing.T) {
				pkgID := pkg.ID("libnghttp2")
				p := rhelIndirectRPMHost("libnghttp2", "nghttp2", rhel92, 0, "0:1.43.0-5.el9_2.3", pkgID)
				db.Match(t, &Matcher{}, p).
					Ignores().
					SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2023-44487").
					ForPackage(pkgID).
					WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
			})

			// A genuinely-vulnerable older curl layer (below the 9.2 fix -23.el9_2.4) must still be
			// reported - and should surface BOTH advisories (the reviewer's "pick up both") and the
			// 9.2 stream fix, not the 9.3 build.
			t.Run("curl below 9.2 fix is reported with both advisories and the 9.2 fix", func(t *testing.T) {
				pkgID := pkg.ID("libcurl-minimal-vuln")
				p := rhelIndirectRPMHost("libcurl-minimal", "curl", rhel92, 0, "0:7.76.1-23.el9_2.1", pkgID)
				// Both curl CVEs are loaded and both are vulnerable below the 9.2 fix; scope to one.
				sf := db.Match(t, &Matcher{}, p).SkipCompleteness().SelectMatch("CVE-2023-38545")
				sf.HasFix(vulnerability.FixStateFixed, "0:7.76.1-23.el9_2.4").
					HasAdvisories("RHSA-2023:6745", "RHSA-2023:5763")
				sf.SelectDetailByType(match.ExactIndirectMatch).AsDistroSearch()
			})
		})
}
