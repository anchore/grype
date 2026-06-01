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

// The fixture (testdata/rhel-multi-rhsa) holds the verbatim record vunnel's RHEL
// provider emits for CVE-2024-8088 after the multi-RHSA phase-1 change: two RHSAs
// fixing python3.9 at distinct upstream bases (the 9.4 Z-stream backport
// 3.9.18-3.el9_4.5 and the 9.5 GA rebase 3.9.19-8.el9) are reduced to a single record
// whose VulnerableRange partitions the two streams:
//
//	< 0:3.9.18-3.el9_4.5 || >= 0:3.9.19, < 0:3.9.19-8.el9
//
// dbtest runs the real grype-db transform over that record, so this validates the
// whole vunnel -> grype-db -> grype matching path, not a hand-built v6 constraint.
//
// See https://access.redhat.com/security/cve/cve-2024-8088#cve-affected-packages

// rhelPython39Host builds the package shape the matcher receives for a RHEL host:
// the python3 binary RPM plus an upstream pointer to its python3.9 source RPM, so the
// matcher's source-indirection path engages (the RHEL data is keyed on the source RPM).
func rhelPython39Host(d *distro.Distro, version string, id pkg.ID) pkg.Package {
	return dbtest.NewPackage("python3", version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithUpstream("python3.9", version).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
		Build()
}

func TestRpmMultiRHSA_CVE2024_8088_PartitionedStreams(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel94 := distro.New(distro.RedHat, "9.4", "")

			cases := []struct {
				name       string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "at lower-stream fix (RHSA-2024:6163)",
					version:    "3.9.18-3.el9_4.5",
					vulnerable: false,
					why:        "host carries the 9.4 Z-stream backport; < 3.9.19 so it falls into no clause",
				},
				{
					name:       "below lower-stream fix",
					version:    "3.9.18-3.el9_4.4",
					vulnerable: true,
					why:        "one Z-stream patch behind the 9.4 fix - genuinely vulnerable",
				},
				{
					name:       "above lower-stream fix, still in 3.9.18 line",
					version:    "3.9.18-10.el9_4",
					vulnerable: false,
					why:        "above the 9.4 fix, still < 3.9.19 - not vulnerable",
				},
				{
					name:       "in 3.9.19 stream below upper-stream fix",
					version:    "3.9.19-1.el9",
					vulnerable: true,
					why:        ">= 3.9.19 and < 3.9.19-8.el9 - pre-RHSA-2024:9371 build is vulnerable",
				},
				{
					name:       "at upper-stream fix (RHSA-2024:9371)",
					version:    "3.9.19-8.el9",
					vulnerable: false,
					why:        "host carries the 9.5 GA fix - not vulnerable",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("python3-" + c.version)
					p := rhelPython39Host(rhel94, c.version, pkgID)
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2024-8088").
							SelectDetailByType(match.ExactIndirectMatch).
							AsDistroSearch()
					} else {
						// not vulnerable: the owned python3 binary yields a "Distro Not
						// Vulnerable" ownership ignore rather than a match.
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-8088").
							ForPackage(pkgID).
							WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
					}
				})
			}
		})
}

// The fix metadata and folded advisories should survive the transform onto the match.
func TestRpmMultiRHSA_CVE2024_8088_FixAndAdvisories(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := rhelPython39Host(distro.New(distro.RedHat, "9.4", ""), "3.9.18-3.el9_4.4", pkg.ID("python3"))

			sf := db.Match(t, &matcher, p).SelectMatch("CVE-2024-8088")
			// canonical fix is the newest stream's build; both RHSAs are surfaced.
			sf.HasFix(vulnerability.FixStateFixed, "0:3.9.19-8.el9").
				HasAdvisories("RHSA-2024:9371", "RHSA-2024:6163")
			sf.SelectDetailByType(match.ExactIndirectMatch).AsDistroSearch()
		})
}

// A host on an older base than either fix (e.g. a 9.2 build that never received a
// targeted backport for this CVE) is below the lowest stream's fix and must stay
// flagged - phase 1 must not over-suppress.
func TestRpmMultiRHSA_CVE2024_8088_OlderBaseStillFlagged(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("CVE-2024-8088").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := rhelPython39Host(distro.New(distro.RedHat, "9.2", ""), "3.9.16-1.el9_2.5", pkg.ID("python3"))

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-8088").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}
