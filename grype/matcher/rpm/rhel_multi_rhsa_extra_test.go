package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// These exercise additional multi-RHSA partitioned-stream records mined from a real
// vunnel cache (see datasources/rhel/scripts/find_multi_rhsa_results.py). They extend
// the CVE-2024-8088/python3.9 coverage in rhel_multi_rhsa_test.go to dimensions that
// case does not touch: a 3-stream partition with an epoch bump mid-range (podman), a
// fold of three advisories including an RHBA (microcode_ctl), and a modular package
// (go-toolset). As with that file, dbtest runs the real grype-db transform over the
// verbatim vunnel record, so these validate the whole vunnel -> grype-db -> grype path.

// rhelDirectRPMHost builds a plain RHEL binary RPM whose name equals the source RPM the
// RHEL data is keyed on, so the matcher's direct path engages (no source indirection).
// epoch is set in metadata so the epoch comparison is exercised explicitly.
func rhelDirectRPMHost(name string, d *distro.Distro, epoch int, version string, id pkg.ID) *dbtest.PackageBuilder {
	return dbtest.NewPackage(name, version, syftPkg.RpmPkg).
		WithID(id).
		WithDistro(d).
		WithMetadata(pkg.RpmMetadata{Epoch: intPtr(epoch)})
}

// CVE-2025-9566 fixes podman in rhel:10 across three upstream bases, and the epoch bumps
// from 6 to 7 between the oldest stream and the newer two. vunnel folds all three RHSAs
// into one record with a three-clause VulnerableRange:
//
//	< 6:5.4.0-13.el10_0 || >= 7:5.6.0, < 7:5.6.0-5.el10_1 || >= 7:5.8.0, < 7:5.8.0-2.el10
//
// The interesting properties versus the python3.9 case: a third stream, and an epoch
// pivot that the >= base clauses must respect (a 6:5.4.0 build is not >= 7:5.6.0).
func TestRpmMultiRHSA_CVE2025_9566_ThreeStreamsWithEpochBump(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("rhel:10/cve-2025-9566").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel10 := distro.New(distro.RedHat, "10.1", "")

			cases := []struct {
				name       string
				epoch      int
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "below lowest-stream fix",
					epoch:      6,
					version:    "6:5.4.0-12.el10_0",
					vulnerable: true,
					why:        "one release behind the 10.0 fix; < 6:5.4.0-13.el10_0",
				},
				{
					name:       "at lowest-stream fix",
					epoch:      6,
					version:    "6:5.4.0-13.el10_0",
					vulnerable: false,
					why:        "carries the 10.0 fix; not >= 7:5.6.0 so it falls into no later clause",
				},
				{
					name:       "in middle stream below its fix",
					epoch:      7,
					version:    "7:5.6.0-3.el10_1",
					vulnerable: true,
					why:        ">= 7:5.6.0 and < 7:5.6.0-5.el10_1",
				},
				{
					name:       "at middle-stream fix",
					epoch:      7,
					version:    "7:5.6.0-5.el10_1",
					vulnerable: false,
					why:        "carries the 10.1 fix",
				},
				{
					name:       "in fixed middle stream, above its fix, below newest base",
					epoch:      7,
					version:    "7:5.7.0-1.el10",
					vulnerable: false,
					why:        ">= 7:5.6.0 but not < 7:5.6.0-5, and not >= 7:5.8.0 - in no clause",
				},
				{
					name:       "in newest stream below its fix",
					epoch:      7,
					version:    "7:5.8.0-1.el10",
					vulnerable: true,
					why:        ">= 7:5.8.0 and < 7:5.8.0-2.el10",
				},
				{
					name:       "at newest-stream fix",
					epoch:      7,
					version:    "7:5.8.0-2.el10",
					vulnerable: false,
					why:        "carries the newest GA fix",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("podman-" + c.version)
					p := rhelDirectRPMHost("podman", rhel10, c.epoch, c.version, pkgID).Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2025-9566").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2025-9566")
					}
				})
			}
		})
}

// The newest stream's build is the canonical fix and all three RHSAs are folded on.
func TestRpmMultiRHSA_CVE2025_9566_FixAndAdvisories(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("rhel:10/cve-2025-9566").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := rhelDirectRPMHost("podman", distro.New(distro.RedHat, "10.1", ""), 6, "6:5.4.0-12.el10_0", pkg.ID("podman")).Build()

			sf := db.Match(t, &matcher, p).SelectMatch("CVE-2025-9566")
			sf.HasFix(vulnerability.FixStateFixed, "7:5.8.0-2.el10").
				HasAdvisories("RHSA-2026:18289", "RHSA-2025:20983", "RHSA-2025:15901")
			sf.SelectDetailByType(match.ExactDirectMatch).AsDistroSearch()
		})
}

// CVE-2020-8696 fixes microcode_ctl in rhel:8 in two upstream bases, but three advisories
// touched the bucket - including an RHBA (a bugfix advisory, not a security one). vunnel
// folds and de-duplicates all three onto the single record. This checks that the fold
// keeps every distinct advisory regardless of RH*A type.
func TestRpmMultiRHSA_CVE2020_8696_FoldsRHBA(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("rhel:8/cve-2020-8696").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// well below the lowest stream's fix (4:20200609-...) - genuinely vulnerable.
			p := rhelDirectRPMHost("microcode_ctl", distro.New(distro.RedHat, "8.3", ""), 4, "4:20191115-4.20200602.2.el8_2", pkg.ID("microcode_ctl")).Build()

			sf := db.Match(t, &matcher, p).SelectMatch("CVE-2020-8696")
			sf.HasFix(vulnerability.FixStateFixed, "4:20210216-1.20210608.1.el8_4").
				HasAdvisories("RHSA-2021:3027", "RHBA-2021:0621", "RHSA-2020:5085")
			sf.SelectDetailByType(match.ExactDirectMatch).AsDistroSearch()
		})
}

func TestRpmMultiRHSA_CVE2020_8696_PartitionedStreams(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("rhel:8/cve-2020-8696").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel8 := distro.New(distro.RedHat, "8.4", "")

			// VulnerableRange:
			//   < 4:20200609-2.20210216.1.el8_3 || >= 4:20210216, < 4:20210216-1.20210608.1.el8_4
			cases := []struct {
				name       string
				version    string
				vulnerable bool
			}{
				{"below lowest-stream fix", "4:20191115-4.20200602.2.el8_2", true},
				{"at lowest-stream fix", "4:20200609-2.20210216.1.el8_3", false},
				{"in newest stream below its fix", "4:20210216-1.20210501.1.el8_4", true},
				{"at newest-stream fix", "4:20210216-1.20210608.1.el8_4", false},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("microcode_ctl-" + c.version)
					p := rhelDirectRPMHost("microcode_ctl", rhel8, 4, c.version, pkgID).Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2020-8696").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2020-8696")
					}
				})
			}
		})
}

// CVE-2023-45288 fixes go-toolset in rhel:8 in two upstream bases within a module
// (Module=go-toolset:rhel8). The partition must hold inside the module-qualified record:
//
//	< 0:1.20.12-1.module+el8.9.0+21033+5795bdf6 || >= 0:1.21.9, < 0:1.21.9-1.module+el8.10.0+21671+b35c3b78
func TestRpmMultiRHSA_CVE2023_45288_ModularPartition(t *testing.T) {
	dbtest.DBs(t, "rhel-multi-rhsa").
		SelectOnly("rhel:8/cve-2023-45288").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel8 := distro.New(distro.RedHat, "8.10", "")

			cases := []struct {
				name       string
				version    string
				vulnerable bool
			}{
				{"below lowest-stream fix", "0:1.20.11-1.module+el8.9.0+20000+aaaaaaaa", true},
				{"at lowest-stream fix", "0:1.20.12-1.module+el8.9.0+21033+5795bdf6", false},
				{"in newest stream below its fix", "0:1.21.9-1.module+el8.10.0+21000+00000000", true},
				{"at newest-stream fix", "0:1.21.9-1.module+el8.10.0+21671+b35c3b78", false},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("go-toolset-" + c.version)
					p := rhelDirectRPMHost("go-toolset", rhel8, 0, c.version, pkgID).
						WithMetadata(pkg.RpmMetadata{
							Epoch:           intPtr(0),
							ModularityLabel: strPtr("go-toolset:rhel8:8100020240426:b35c3b78"),
						}).
						Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2023-45288").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2023-45288")
					}
				})
			}
		})
}
