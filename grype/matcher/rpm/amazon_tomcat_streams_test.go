package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The fixture (testdata/amazon-tomcat-streams) holds real Amazon Linux 2 advisory records for the
// tomcat source rpm in OS schema; see its db.yaml for what each record is.

// amazonTomcat7Host is a binary rpm whose advisories are keyed on its source rpm ("tomcat"), from
// docker.io/anchore/test_images:vulnerabilities-amazonlinux-2:
//
//	tomcat-servlet-3.0-api 0:7.0.76-10.amzn2.0.2, sourceRpm tomcat-7.0.76-10.amzn2.0.2.src.rpm
func amazonTomcat7Host(id pkg.ID) pkg.Package {
	return dbtest.NewPackage("tomcat-servlet-3.0-api", "0:7.0.76-10.amzn2.0.2", syftPkg.RpmPkg).
		WithID(id).
		WithArchitecture("noarch").
		WithDistro(distro.New(distro.AmazonLinux, "2", "")).
		WithUpstream("tomcat", "7.0.76-10.amzn2.0.2").
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

// An advisory this build is past must still reach the caller as an ownership ignore (suppressing CPE
// findings on the jars this rpm contains) when an advisory from another release line is reported for
// a CVE they share. The two pairings differ in how many aliases the resolved advisory names:
//
//	ALAS2-2020-1402 (5 CVEs)  vs ALAS2TOMCAT8.5-2023-012, sharing CVE-2020-1938
//	ALAS2-2020-1449 (1 CVE)   vs ALAS2TOMCAT8.5-2023-008, sharing CVE-2020-9484
func TestAmazonTomcatStreams_UpstreamHitDoesNotDenyDirectFix(t *testing.T) {
	dbtest.DBs(t, "amazon-tomcat-streams").
		Run(func(t *testing.T, db *dbtest.DB) {
			pkgID := pkg.ID("tomcat-servlet-3.0-api")
			matcher := Matcher{}

			findings := db.Match(t, &matcher, amazonTomcat7Host(pkgID))

			// only the tomcat8.5 advisories cover a 7.0.76 build
			findings.SelectMatch("ALAS2TOMCAT8.5-2023-008").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch("< 8.5.56-1.amzn2 (rpm)")
			findings.SelectMatch("ALAS2TOMCAT8.5-2023-012").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch("< 8.5.51-1.amzn2 (rpm)")

			// the tomcat 7 advisories this build is at or past, under their own IDs and every CVE
			// they name, including the CVEs shared with the reported advisories
			findings.Ignores().
				SelectRelatedPackageIgnores(IgnoreReasonDistroNotVulnerable,
					"ALAS2-2020-1402",
					"CVE-2018-1304", "CVE-2018-1305", "CVE-2018-8014", "CVE-2018-8034", "CVE-2020-1938",
					"ALAS2-2020-1449",
					"CVE-2020-9484",
				).
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}
