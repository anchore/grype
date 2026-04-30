package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestShouldUseAlmaLinuxMatching(t *testing.T) {
	tests := []struct {
		name     string
		distro   *distro.Distro
		expected bool
	}{
		{
			name:     "nil distro",
			distro:   nil,
			expected: false,
		},
		{
			name: "AlmaLinux distro",
			distro: &distro.Distro{
				Type: distro.AlmaLinux,
			},
			expected: true,
		},
		{
			name: "RHEL distro",
			distro: &distro.Distro{
				Type: distro.RedHat,
			},
			expected: false,
		},
		{
			name: "Ubuntu distro",
			distro: &distro.Distro{
				Type: distro.Ubuntu,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldUseAlmaLinuxMatching(tt.distro)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// alma8 is used by tests below.
var alma8 = distro.New(distro.AlmaLinux, "8", "")

// TestAlmaLinuxMatching_ModularVulnerable verifies that a modular package whose
// version is below both the RHEL and AlmaLinux fix versions reports as
// vulnerable, and that the AlmaLinux fix info (with .alma suffix) replaces
// the RHEL fix info on the resulting Match.
func TestAlmaLinuxMatching_ModularVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd 2.4.37-30 is below both RHEL fix (-39) and AlmaLinux fix (-43)
			p := dbtest.NewPackage("httpd", "2.4.37-30.module_el8.3.0+1234+abcd", syftPkg.RpmPkg).
				WithDistro(alma8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intRef(0),
					ModularityLabel: strRef("httpd:2.4:1234:5678"),
				}).
				Build()

			matches, _, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.Len(t, matches, 1, "expected one match")

			m := matches[0]
			assert.Equal(t, "CVE-2021-40438", m.Vulnerability.ID)
			// fix info should be from AlmaLinux ALSA, not RHEL
			require.Equal(t, vulnerability.FixStateFixed, m.Vulnerability.Fix.State)
			require.Equal(t, []string{"2.4.37-43.module_el8.5.0+2597+c4b14997.alma"}, m.Vulnerability.Fix.Versions)
			// advisory should reference ALSA-2021:4537
			require.Len(t, m.Vulnerability.Advisories, 1)
			assert.Equal(t, "ALSA-2021:4537", m.Vulnerability.Advisories[0].ID)
		})
}

// TestAlmaLinuxMatching_ModularFixed verifies that a modular package at or past
// the RHEL fix version is filtered out and produces a "Distro Fixed" ignore
// (the package is not vulnerable per RHEL, so AlmaLinux logic isn't even
// reached for filtering).
func TestAlmaLinuxMatching_ModularFixed(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd at exact AlmaLinux fix version (which is past the RHEL fix)
			pkgID := pkg.ID("httpd-fixed")
			p := dbtest.NewPackage("httpd", "2.4.37-43.module_el8.5.0+2597+c4b14997.alma", syftPkg.RpmPkg).
				WithDistro(alma8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intRef(0),
					ModularityLabel: strRef("httpd:2.4:1234:5678"),
				}).
				Build()
			p.ID = pkgID

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			assert.Empty(t, matches, "fixed package should not produce matches")
			assert.NotEmpty(t, ignores, "fixed package should produce ignore filter")

			// the rhel disclosure path produces "Distro Fixed" since the binary
			// package version is past the RHEL fix
			foundDistroFixed := false
			for _, ig := range ignores {
				if irp, ok := ig.(match.IgnoreRelatedPackage); ok {
					if irp.Reason == "Distro Fixed" && irp.VulnerabilityID == "CVE-2021-40438" {
						foundDistroFixed = true
					}
				}
			}
			assert.True(t, foundDistroFixed, "expected Distro Fixed ignore filter for CVE-2021-40438")
		})
}

// TestAlmaLinuxMatching_ModularityMismatch verifies that a package in a
// different module than the vulnerability does not match.
func TestAlmaLinuxMatching_ModularityMismatch(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd in a different module - no match
			p := dbtest.NewPackage("httpd", "2.4.37-30.module_el8.3.0+1234+abcd", syftPkg.RpmPkg).
				WithDistro(alma8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intRef(0),
					ModularityLabel: strRef("httpd:2.6:1234:5678"),
				}).
				Build()

			matches, _, err := matcher.Match(db, p)
			require.NoError(t, err)
			assert.Empty(t, matches, "module mismatch should not match")
		})
}

// TestAlmaLinuxMatching_NonModularVulnerable verifies that a non-modular
// vulnerable package matches via AlmaLinux logic and the fix info is preserved
// (the AlmaLinux fix here matches the RHEL fix exactly, so no replacement).
func TestAlmaLinuxMatching_NonModularVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// patch 2.7.6-10 < fix 2.7.6-11
			p := dbtest.NewPackage("patch", "2.7.6-10.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				Build()

			matches, _, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.Len(t, matches, 1)

			m := matches[0]
			assert.Equal(t, "CVE-2019-13636", m.Vulnerability.ID)
			// AlmaLinux matching searches the RHEL namespace for disclosures
			assert.Equal(t, "redhat:distro:redhat:8", m.Vulnerability.Namespace)
			require.NotEmpty(t, m.Details)
			assert.Equal(t, match.ExactDirectMatch, m.Details[0].Type)
		})
}

// TestAlmaLinuxMatching_NonModularFixed verifies that a non-modular package at
// the fix version is not vulnerable and produces an ignore filter.
func TestAlmaLinuxMatching_NonModularFixed(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("patch-fixed")
			p := dbtest.NewPackage("patch", "2.7.6-11.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				Build()
			p.ID = pkgID

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			assert.Empty(t, matches, "fixed package should not produce matches")
			require.NotEmpty(t, ignores, "fixed package should produce ignore filter")

			foundDistroFixed := false
			for _, ig := range ignores {
				if irp, ok := ig.(match.IgnoreRelatedPackage); ok {
					if irp.Reason == "Distro Fixed" && irp.VulnerabilityID == "CVE-2019-13636" {
						foundDistroFixed = true
					}
				}
			}
			assert.True(t, foundDistroFixed, "expected Distro Fixed ignore for CVE-2019-13636")
		})
}

// TestAlmaLinuxMatching_WontFixPassesThrough verifies that a RHEL "won't fix"
// vulnerability with no AlmaLinux advisory still reports the vulnerability with
// the won't-fix state preserved.
func TestAlmaLinuxMatching_WontFixPassesThrough(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2005-2541").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("tar", "2:1.30-5.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(2)}).
				Build()

			matches, _, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.Len(t, matches, 1)

			m := matches[0]
			assert.Equal(t, "CVE-2005-2541", m.Vulnerability.ID)
			assert.Equal(t, vulnerability.FixStateWontFix, m.Vulnerability.Fix.State)
		})
}

// TestAlmaLinuxMatching_DebuginfoSkipped verifies that -debuginfo and
// -debugsource packages are skipped (AlmaLinux never publishes advisories for
// debug-only RPMs).
func TestAlmaLinuxMatching_DebuginfoSkipped(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("patch-debuginfo", "2.7.6-10.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				WithUpstream("patch", "2.7.6-10.el8").
				Build()

			matches, _, err := matcher.Match(db, p)
			require.NoError(t, err)
			assert.Empty(t, matches, "-debuginfo packages should be skipped by AlmaLinux matching")
		})
}

// TestAlmaLinuxIgnoreFilters_NoIgnoresWhenVulnerable verifies that a still-
// vulnerable package produces a match and no ignore filters.
func TestAlmaLinuxIgnoreFilters_NoIgnoresWhenVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("patch", "2.7.6-1.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				Build()

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.NotEmpty(t, matches, "vulnerable package should produce a match")
			require.Empty(t, ignores, "vulnerable package should not produce ignore filters")
		})
}

// TestAlmaLinuxIgnoreFilters_DistroFixedIgnore verifies that a non-vulnerable
// (already-fixed) package produces a "Distro Fixed" IgnoreRelatedPackage.
func TestAlmaLinuxIgnoreFilters_DistroFixedIgnore(t *testing.T) {
	dbtest.DBs(t, "alma8-real").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("patch-fixed")
			p := dbtest.NewPackage("patch", "2.7.6-12.el8", syftPkg.RpmPkg).
				WithDistro(alma8).
				Build()
			p.ID = pkgID

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			assert.Empty(t, matches, "fixed package should not produce matches")

			// expect Distro Fixed ignore for CVE-2019-13636
			distroFixedFound := false
			for _, ig := range ignores {
				if irp, ok := ig.(match.IgnoreRelatedPackage); ok {
					if irp.Reason == "Distro Fixed" && irp.VulnerabilityID == "CVE-2019-13636" && irp.RelatedPackageID == pkgID {
						distroFixedFound = true
					}
				}
			}
			assert.True(t, distroFixedFound, "expected Distro Fixed ignore filter")
		})
}
