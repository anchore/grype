package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
)

// Same-base multi-stream RHEL fixes: Red Hat patches one package at the SAME upstream
// base across several minors (e.g. firefox 128.4.0 rebuilt as -1.el9_4 and -1.el9_5).
// No VulnerableRange can separate these - the leading release is a single total order, so
// vunnel collapses them to the highest-EVR build and a host running its own stream's fix
// is falsely flagged. The fix: vunnel emits an UnaffectedVersions list of every called-out
// fix EVR, the OS transformer turns each into a "= <evr>" unaffected handle, and the
// matcher lets an exact-fix unaffected record suppress the coarse "below highest" match.
//
// These tests assert the post-fix behavior; they fail against the unmodified
// transformer+matcher (the host-at-its-stream-fix cases report a false positive).

func TestRpmSameBaseRHSA_Firefox_DistTagOnly(t *testing.T) {
	dbtest.DBs(t, "rhel-same-base-rhsa").
		SelectOnly("rhel:9/cve-2024-10458").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel9 := distro.New(distro.RedHat, "9.4", "")

			cases := []struct {
				name       string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "host at the 9.4 stream fix",
					version:    "0:128.4.0-1.el9_4",
					vulnerable: false,
					why:        "exact called-out fix for the 9.4 branch; only the dist tag makes it < the 9.5 build",
				},
				{
					name:       "host at the 9.5 stream fix",
					version:    "0:128.4.0-1.el9_5",
					vulnerable: false,
					why:        "exact called-out fix for the 9.5 branch (also the collapsed highest)",
				},
				{
					name:       "host genuinely below all fixes",
					version:    "0:128.3.0-1.el9_4",
					vulnerable: true,
					why:        "older upstream than either fix and matches no unaffected handle",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("firefox-" + c.version)
					p := rhelDirectRPMHost("firefox", rhel9, 0, c.version, pkgID).Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2024-10458").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2024-10458")
					}
				})
			}
		})
}

// The inverted case: by EVR the GA `.el8` build (425.3.1) outranks the 8.6 EUS backport
// (372.26.1), so the collapsed highest is the GA build and an 8.6 host at its own fix is
// flagged. The exact-fix unaffected handle must rescue it.
func TestRpmSameBaseRHSA_Kernel_Inverted(t *testing.T) {
	dbtest.DBs(t, "rhel-same-base-rhsa").
		SelectOnly("rhel:8/cve-2022-48943").
		Run(func(t *testing.T, db *dbtest.DB) {
			rhel8 := distro.New(distro.RedHat, "8.6", "")

			cases := []struct {
				name       string
				version    string
				vulnerable bool
				why        string
			}{
				{
					name:       "host at the 8.6 EUS stream fix",
					version:    "0:4.18.0-372.26.1.el8_6",
					vulnerable: false,
					why:        "exact 8.6 fix; EVR ranks it below the GA build only because 372 < 425",
				},
				{
					name:       "host at the GA stream fix",
					version:    "0:4.18.0-425.3.1.el8",
					vulnerable: false,
					why:        "exact GA fix (the collapsed highest)",
				},
				{
					name:       "host genuinely below its stream fix",
					version:    "0:4.18.0-300.10.1.el8_6",
					vulnerable: true,
					why:        "below the 8.6 fix and matches no unaffected handle",
				},
			}

			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					matcher := Matcher{}
					pkgID := pkg.ID("kernel-" + c.version)
					p := rhelDirectRPMHost("kernel", rhel8, 0, c.version, pkgID).Build()
					if c.vulnerable {
						db.Match(t, &matcher, p).
							SelectMatch("CVE-2022-48943").
							SelectDetailByType(match.ExactDirectMatch).
							AsDistroSearch()
					} else {
						db.Match(t, &matcher, p).
							Ignores().
							SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2022-48943")
					}
				})
			}
		})
}
