package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// oracle7 is the distro a scanned Oracle Linux 7 package carries.
var oracle7 = distro.New(distro.OracleLinux, "7", "")

// TestOraclePerArchFix_NoFalsePositiveOnPatchedArch is the end-to-end regression for the
// ELSA-2022-4803 false positive. Oracle respun the aarch64 rsyslog at a higher revision
// (.0.4) than the x86_64 build (.0.1); vunnel records that as two FixedIn entries with distinct
// Arch, and the os transformer emits one affected package handle per arch carrying an
// Architecture qualifier. So a patched x86_64 rsyslog (.0.1) must NOT be flagged by the aarch64
// fix, while an aarch64 build at the same version still is (it's below the aarch64 fix). Before
// arch was carried through to a qualifier, the higher .0.4 constraint falsely flagged the
// patched x86_64 package.
func TestOraclePerArchFix_NoFalsePositiveOnPatchedArch(t *testing.T) {
	dbtest.DBs(t, "oracle").
		SelectOnly("ol:7/elsa-2022-4803").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// x86_64 host patched to the x86_64 fix (.0.1) must NOT be reported vulnerable: the
			// aarch64-scoped .0.4 record is the FP we're preventing. Instead the matcher recognizes
			// the package is at the x86_64 fix and emits a "Distro Not Vulnerable" ignore for the
			// advisory and its CVE alias — exactly the patched-but-acknowledged outcome.
			patchedX86 := dbtest.NewPackage("rsyslog", "0:8.24.0-57.0.1.el7_9.3", syftPkg.RpmPkg).
				WithArchitecture("x86_64").
				WithDistro(oracle7).
				Build()
			patched := db.Match(t, &matcher, patchedX86)
			patched.DoesNotHaveAnyVulnerabilities("ELSA-2022-4803", "CVE-2022-24903")
			patched.Ignores().SelectRelatedPackageIgnores(IgnoreReasonDistroNotVulnerable, "ELSA-2022-4803", "CVE-2022-24903")

			// an aarch64 build at the same version is still below the aarch64 fix (.0.4) → vulnerable.
			vulnerableArm := dbtest.NewPackage("rsyslog", "0:8.24.0-57.0.1.el7_9.3", syftPkg.RpmPkg).
				WithArchitecture("aarch64").
				WithDistro(oracle7).
				Build()
			db.Match(t, &matcher, vulnerableArm).
				SelectMatch("ELSA-2022-4803").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}
