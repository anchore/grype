package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"

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

// TestAlmaLinuxMatching_ModularVulnerable verifies that a modular package whose
// version is below both the RHEL and AlmaLinux fix versions reports as
// vulnerable, and that the AlmaLinux fix info (with .alma suffix) replaces
// the RHEL fix info on the resulting Match.
func TestAlmaLinuxMatching_ModularVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd 2.4.37-30 is below both RHEL fix (-39) and AlmaLinux fix (-43)
			p := dbtest.NewPackage("httpd", "2.4.37-30.module_el8.3.0+1234+abcd", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.4:1234:5678"),
				}).
				Build()

			findings := db.Match(t, &matcher, p).HasCount(1)
			sf := findings.SelectMatch("CVE-2021-40438")
			// fix info should be from AlmaLinux ALSA, not RHEL
			sf.HasFix(vulnerability.FixStateFixed, "2.4.37-43.module_el8.5.0+2597+c4b14997.alma").
				HasAdvisories("ALSA-2021:4537")
			sf.SelectDetailByDistro("redhat", "8"). // alma matching queries the rhel namespace
								HasMatchType(match.ExactDirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxMatching_ModularFixed verifies that a modular package at or past
// the RHEL fix version is filtered out and produces a "Distro Fixed" ignore
// (the package is not vulnerable per RHEL, so AlmaLinux logic isn't even
// reached for filtering).
func TestAlmaLinuxMatching_ModularFixed(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd at exact AlmaLinux fix version (which is past the RHEL fix)
			pkgID := pkg.ID("httpd-fixed")
			p := dbtest.NewPackage("httpd", "2.4.37-43.module_el8.5.0+2597+c4b14997.alma", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.4:1234:5678"),
				}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			// the rhel disclosure path produces "Distro Fixed" since the binary
			// package version is past the RHEL fix
			findings.Ignores().
				HasCount(1).
				SelectRelatedPackageIgnore("Distro Fixed", "CVE-2021-40438").
				ForPackage(pkgID)
		})
}

// TestAlmaLinuxMatching_ModularityMismatch verifies that a package in a
// different module than the vulnerability does not match.
func TestAlmaLinuxMatching_ModularityMismatch(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd in a different module - no match
			p := dbtest.NewPackage("httpd", "2.4.37-30.module_el8.3.0+1234+abcd", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.6:1234:5678"),
				}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestAlmaLinuxMatching_NonModularVulnerable verifies that a non-modular
// vulnerable package matches via AlmaLinux logic and the fix info is preserved
// (the AlmaLinux fix here matches the RHEL fix exactly, so no replacement).
func TestAlmaLinuxMatching_NonModularVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// patch 2.7.6-10 < fix 2.7.6-11
			p := dbtest.NewPackage("patch", "2.7.6-10.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				Build()

			findings := db.Match(t, &matcher, p).HasCount(1)
			findings.SelectMatch("CVE-2019-13636").
				// AlmaLinux matching searches the RHEL namespace for disclosures
				InNamespace("redhat:distro:redhat:8").
				SelectDetailByDistro("redhat", "8").
				HasMatchType(match.ExactDirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxMatching_NonModularFixed verifies that a non-modular package at
// the fix version is not vulnerable and produces an ignore filter.
func TestAlmaLinuxMatching_NonModularFixed(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("patch-fixed")
			p := dbtest.NewPackage("patch", "2.7.6-11.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.AlmaLinux8).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().
				HasCount(1).
				SelectRelatedPackageIgnore("Distro Fixed", "CVE-2019-13636").
				ForPackage(pkgID)
		})
}

// TestAlmaLinuxMatching_WontFixPassesThrough verifies that a RHEL "won't fix"
// vulnerability with no AlmaLinux advisory still reports the vulnerability with
// the won't-fix state preserved.
func TestAlmaLinuxMatching_WontFixPassesThrough(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2005-2541").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("tar", "2:1.30-5.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(2)}).
				Build()

			findings := db.Match(t, &matcher, p).HasCount(1)
			sf := findings.SelectMatch("CVE-2005-2541")
			sf.HasFix(vulnerability.FixStateWontFix)
			sf.SelectDetailByDistro("redhat", "8").
				HasMatchType(match.ExactDirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxMatching_UpstreamMatchWithFixReplacement verifies the upstream
// path of alma matching with fix replacement: a binary package (httpd-tools)
// reaches a vulnerable source package (httpd) via upstream, the alma matcher
// finds it through the source RPM relation, and the resulting Match's fix info
// is replaced with the alma-specific fix (ALSA-2021:4537's
// "2.4.37-43.module_el8.5.0+2597+c4b14997.alma") rather than the RHEL fix
// ("0:2.4.37-39.module+el8.4.0+9658+b87b2deb").
func TestAlmaLinuxMatching_UpstreamMatchWithFixReplacement(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-40438", "almalinux8/alsa-2021:4537").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd-tools binary at the same vulnerable version, upstream is httpd
			p := dbtest.NewPackage("httpd-tools", "2.4.37-30.module_el8.3.0+1234+abcd", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithUpstream("httpd", "2.4.37-30.module_el8.3.0+1234+abcd").
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.4:1234:5678"),
				}).
				Build()

			findings := db.Match(t, &matcher, p).HasCount(1)
			sf := findings.SelectMatch("CVE-2021-40438")
			// alma fix version should replace the rhel fix on upstream-resolved matches
			sf.HasFix(vulnerability.FixStateFixed, "2.4.37-43.module_el8.5.0+2597+c4b14997.alma")
			sf.SelectDetailByDistro("redhat", "8"). // alma matching queries the rhel namespace
								HasMatchType(match.ExactIndirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxMatching_LowerAlmaModuleBuildFiltersVulnerability is the
// canonical reason the alma matcher exists rather than "just use the RHEL
// data". RHEL and AlmaLinux ship the same source build for a given fix (same
// hash suffix in the module version, e.g. "+7adc332a") but use different
// module build counters: RHEL uses higher counters than AlmaLinux. For
// CVE-2021-27928 mariadb:10.3:
//
//	rhel:  3:10.3.28-1.module+el8.3.0+10472+7adc332a   (build 10472)
//	alma:  3:10.3.28-1.module_el8.3.0+2177+7adc332a    (build 2177)
//
// A package on AlmaLinux at the alma fix version (build 2177) is at the
// equivalent fix in alma terms, but a naive RHEL-only comparison would say it
// is BELOW the RHEL fix (2177 < 10472) and report a false-positive
// vulnerability. The alma matcher must recognize the alma build as the fix
// and produce only ignores. Asserts: 0 matches, 2 "Alma Unaffected" ignores
// (the ALSA itself plus the alias-unwound CVE).
func TestAlmaLinuxMatching_LowerAlmaModuleBuildFiltersVulnerability(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-27928", "almalinux8/alsa-2021:1242").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("mariadb-at-alma-fix")
			p := dbtest.NewPackage("mariadb", "3:10.3.28-1.module_el8.3.0+2177+7adc332a", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(3),
					ModularityLabel: strPtr("mariadb:10.3:1234:abcd"),
				}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()

			igs := findings.Ignores().HasCount(2)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "ALSA-2021:1242").ForPackage(pkgID)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "CVE-2021-27928").ForPackage(pkgID)
		})
}

// TestAlmaLinuxMatching_BelowBothModuleBuildsStillVulnerable is the companion
// to LowerAlmaModuleBuildFiltersVulnerability: a package at a version below
// BOTH the rhel fix and the alma fix is still reported as vulnerable, with
// the alma fix info replacing the rhel fix info (same fix-replacement path
// covered by NonModular tests, but exercised here on a modular package where
// the build-counter difference is real).
func TestAlmaLinuxMatching_BelowBothModuleBuildsStillVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2021-27928", "almalinux8/alsa-2021:1242").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// 10.3.27 < both fix versions (alma 10.3.28 and rhel 10.3.28)
			p := dbtest.NewPackage("mariadb", "3:10.3.27-3.module_el8.3.0+1234+abcdef", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(3),
					ModularityLabel: strPtr("mariadb:10.3:1234:abcd"),
				}).
				Build()

			findings := db.Match(t, &matcher, p).HasCount(1)
			sf := findings.SelectMatch("CVE-2021-27928")
			// fix info should reflect the alma build (2177), not the rhel build (10472)
			sf.HasFix(vulnerability.FixStateFixed, "3:10.3.28-1.module_el8.3.0+2177+7adc332a")
			sf.SelectDetailByDistro("redhat", "8"). // alma matching queries the rhel namespace
								HasMatchType(match.ExactDirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxMatching_DebuginfoSkipped verifies that -debuginfo and
// -debugsource packages are skipped (AlmaLinux never publishes advisories for
// debug-only RPMs).
func TestAlmaLinuxMatching_DebuginfoSkipped(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("patch-debuginfo", "2.7.6-10.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				WithUpstream("patch", "2.7.6-10.el8").
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestAlmaLinuxIgnoreFilters_NoIgnoresWhenVulnerable verifies that a still-
// vulnerable package produces a match and no ignore filters.
func TestAlmaLinuxIgnoreFilters_NoIgnoresWhenVulnerable(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("patch", "2.7.6-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.AlmaLinux8).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2019-13636").
				SelectDetailByDistro("redhat", "8"). // alma matching queries the rhel namespace
				HasMatchType(match.ExactDirectMatch)
			findings.Ignores().IsEmpty()
		})
}

// TestAlmaLinuxIgnoreFilters_DistroFixedIgnore verifies that a non-vulnerable
// (already-fixed) package produces a "Distro Fixed" IgnoreRelatedPackage.
func TestAlmaLinuxIgnoreFilters_DistroFixedIgnore(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly("rhel:8/cve-2019-13636", "almalinux8/alsa-2020:1852").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("patch-fixed")
			p := dbtest.NewPackage("patch", "2.7.6-12.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.AlmaLinux8).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()
			findings.Ignores().
				HasCount(1).
				SelectRelatedPackageIgnore("Distro Fixed", "CVE-2019-13636").
				ForPackage(pkgID)
		})
}

// TestAlmaLinuxIgnoreFilters_AlmaUnaffectedAndAliasUnwind covers two related
// alma-specific behaviors at once:
//   - the "Alma Unaffected" ignore reason (alma matcher emits this when the
//     ALSA's fix range marks the package as not vulnerable)
//   - alias unwinding: ALSA-2021:4537 references three CVEs (40438, 26691,
//     20325). When the ALSA marks the package unaffected, the matcher emits
//     a separate "Alma Unaffected" ignore for the ALSA itself plus one for
//     each related CVE.
//
// The fixture also has RHEL disclosures for CVE-2021-40438 and CVE-2021-26691
// that the package is past, so those produce additional "Distro Fixed"
// ignores - exercising the "mixed reasons in one call" path simultaneously.
// CVE-2021-20325 has no rhel-namespace disclosure that intersects this pkg
// version, so it only appears via the alma alias unwind.
func TestAlmaLinuxIgnoreFilters_AlmaUnaffectedAndAliasUnwind(t *testing.T) {
	dbtest.DBs(t, "alma8").
		SelectOnly(
			"rhel:8/cve-2021-40438",
			"rhel:8/cve-2021-26691",
			"rhel:8/cve-2021-20325",
			"almalinux8/alsa-2021:4537",
		).
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("httpd-multi-cve-fixed")
			p := dbtest.NewPackage("httpd", "2.4.37-43.module_el8.5.0+2597+c4b14997.alma", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.AlmaLinux8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.4:1234:5678"),
				}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.IsEmpty()

			igs := findings.Ignores().HasCount(6)

			// the rhel disclosure path emits "Distro Fixed" for the two CVEs
			// whose RHEL fix the package is past
			igs.SelectRelatedPackageIgnore("Distro Fixed", "CVE-2021-40438").ForPackage(pkgID)
			igs.SelectRelatedPackageIgnore("Distro Fixed", "CVE-2021-26691").ForPackage(pkgID)

			// the alma matcher emits "Alma Unaffected" for the ALSA itself
			// AND for each CVE the ALSA references (alias unwind)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "ALSA-2021:4537").ForPackage(pkgID)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "CVE-2021-40438").ForPackage(pkgID)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "CVE-2021-26691").ForPackage(pkgID)
			igs.SelectRelatedPackageIgnore("Alma Unaffected", "CVE-2021-20325").ForPackage(pkgID)
		})
}
