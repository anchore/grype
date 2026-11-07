package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// oracle9 is the distro a scanned Oracle Linux 9 package carries.
var oracle9 = distro.New(distro.OracleLinux, "9", "")

// TestOracleFIPS_NoFalsePositiveOnStandardPackage is the regression for
// https://github.com/anchore/grype/issues/3750.
//
// Oracle Linux FIPS packages carry epoch 10 and a "_fips" release suffix
// (e.g. 10:3.0.7-28.0.1.el9_4_fips). Because epoch 10 > epoch 1, a standard
// non-FIPS package at epoch 1 always appears "older than the fix" and was
// permanently flagged as vulnerable. The fix requires that a "_fips"-suffixed
// fix version only matches packages whose own version also carries the suffix.
func TestOracleFIPS_NoFalsePositiveOnStandardPackage(t *testing.T) {
	dbtest.DBs(t, "oracle-fips").
		SelectOnly("ol:9/elsa-2024-12345").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// A standard non-FIPS openssl on OL9 at epoch 1 must NOT be reported
			// vulnerable to a FIPS-only advisory whose fix is at epoch 10 + _fips.
			standardPkg := dbtest.NewPackage("openssl", "1:3.5.8-1.0.1.el9_8", syftPkg.RpmPkg).
				WithArchitecture("x86_64").
				WithDistro(oracle9).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			db.Match(t, &matcher, standardPkg).
				DoesNotHaveAnyVulnerabilities("ELSA-2024-12345", "CVE-2024-12345")
		})
}

func TestOracleFIPS_TruePositiveOnFIPSPackage(t *testing.T) {
	dbtest.DBs(t, "oracle-fips").
		SelectOnly("ol:9/elsa-2024-12345").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// A FIPS openssl at epoch 10 below the fix version must still be
			// reported vulnerable (true positive preserved).
			fipsPkg := dbtest.NewPackage("openssl", "10:3.0.7-27.0.1.el9_3_fips", syftPkg.RpmPkg).
				WithArchitecture("x86_64").
				WithDistro(oracle9).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(10)}).
				Build()

			db.Match(t, &matcher, fipsPkg).
				SelectMatch("ELSA-2024-12345").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestOracleFIPS_NoFalseNegativeOnPatchedFIPSPackage(t *testing.T) {
	dbtest.DBs(t, "oracle-fips").
		SelectOnly("ol:9/elsa-2024-12345").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// A FIPS openssl already at the fix version must NOT be reported
			// vulnerable; the matcher emits a "Distro Not Vulnerable" ignore
			// for the advisory and its CVE alias, same as a patched non-FIPS package.
			patchedFIPS := dbtest.NewPackage("openssl", "10:3.0.7-28.0.1.el9_4_fips", syftPkg.RpmPkg).
				WithArchitecture("x86_64").
				WithDistro(oracle9).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(10)}).
				Build()

			db.Match(t, &matcher, patchedFIPS).Ignores().
				SelectRelatedPackageIgnores(IgnoreReasonDistroNotVulnerable, "ELSA-2024-12345", "CVE-2024-12345")
		})
}
