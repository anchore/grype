package rpm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpm_DirectMatch(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// openssl 1:1.1.1b-1 is older than the RHEL 8 fix 1:1.1.1c-2.el8
			p := dbtest.NewPackage("openssl", "1:1.1.1b-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-0735").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherRpm_IndirectMatchBySource(t *testing.T) {
	// the openssl-libs binary RPM is owned by upstream openssl source RPM;
	// the RHEL secdb only carries the source-level entry, so this exercises
	// the upstream/source indirection path.
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl-libs", "1:1.1.1b-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithUpstream("openssl", "1:1.1.1b-1.el8").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-0735").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherRpm_FixedVersionNoMatch(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// version newer than fix - not vulnerable, but matcher still emits
			// a "Distro Not Vulnerable" ignore so consumers can suppress related
			// matches (e.g., GHSA-language matches that overlap by file ownership)
			p := dbtest.NewPackage("openssl", "1:1.1.1c-2.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-0735")
		})
}

func TestMatcherRpm_ModularityLabelMatchesVulnInSameModule(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-17199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// httpd in the httpd:2.4 module - the RHEL fix is in module httpd:2.4
			p := dbtest.NewPackage("httpd", "0:2.4.37-30.module+el8.3.0+1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.4:1234:5678"),
				}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-17199").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherRpm_PackageWithoutModularityLabelMatchesModuleVuln verifies that
// a package with no ModularityLabel still matches a vuln record that has a
// module qualifier set. The "no label" case represents older RPM packages that
// predate the modular RPM scheme; the matcher must not exclude them simply
// because the vuln record specifies a module.
func TestMatcherRpm_PackageWithoutModularityLabelMatchesModuleVuln(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-17199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// CVE-2018-17199 has Module="httpd:2.4"; pkg has no ModularityLabel
			p := dbtest.NewPackage("httpd", "0:2.4.37-30.module+el8.3.0+1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-17199").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherRpm_ModularityLabelMismatchSkipsVuln(t *testing.T) {
	// the vuln is for httpd:2.4 module; package in a different module should not match
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-17199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("httpd", "0:2.4.37-30.module+el8.3.0+1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{
					Epoch:           intPtr(0),
					ModularityLabel: strPtr("httpd:2.6:1234:5678"),
				}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

// TestMatcherRpm_PackageWithoutEpochAssumesZero verifies that a package with no
// epoch (neither in the version string nor in metadata) is compared as epoch 0.
// CVE-2018-0735's openssl fix is "1:1.1.1c-2.el8" (epoch 1). A package at
// "1.1.1z-99.el8" — newer than the fix in version+release terms but with no
// epoch — must be reported as vulnerable: with assumed epoch 0 (< 1), it is
// older than the fix purely by epoch comparison. If the assume-zero logic
// regressed (e.g., the package's missing epoch caused the comparison to be
// skipped or interpreted as "newer"), this test would fail.
func TestMatcherRpm_PackageWithoutEpochAssumesZero(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "1.1.1z-99.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-0735").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherRpm_PackageEpochOnlyInMetadata verifies that an epoch present only
// in pkg.RpmMetadata.Epoch (not in the version string) is honored. The package
// version "1.1.1c-2.el8" at face value would equal the CVE-2018-0735 fix
// "1:1.1.1c-2.el8", but with metadata epoch 0 the package is at epoch 0, the
// fix is at epoch 1, so the package is older and matches.
func TestMatcherRpm_PackageEpochOnlyInMetadata(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "1.1.1c-2.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(0)}).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2018-0735").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

// TestMatcherRpm_PackageHigherEpochNoMatch verifies that a package with an
// explicit epoch HIGHER than the fix epoch is treated as newer-than-fix and
// therefore not vulnerable. Even though "1.1.1b" < "1.1.1c" in the version
// string, epoch 2 > epoch 1 wins the comparison.
func TestMatcherRpm_PackageHigherEpochNoMatch(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "2:1.1.1b-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(2)}).
				Build()

			// not vulnerable -> "Distro Not Vulnerable" ignore (no match)
			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-0735")
		})
}

// TestMatcherRpm_DistroNotVulnerableIgnore exercises the rpm standard-matcher
// ignore path: when a RHEL CVE record exists for a package but the package
// version is at or past the fix, the matcher emits a "Distro Not Vulnerable"
// IgnoreRelatedPackage filter so consumers can suppress related-package matches
// (e.g. GHSA-language matches that overlap by file ownership).
func TestMatcherRpm_DistroNotVulnerableIgnore(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// openssl 1:1.1.1d-1.el8 is past the RHEL 8 fix 1:1.1.1c-2.el8 → not vulnerable
			pkgID := pkg.ID("openssl-fixed")
			p := dbtest.NewPackage("openssl", "1:1.1.1d-1.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-0735").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_DistroNotVulnerableIgnoreViaUpstream verifies the same ignore
// behavior is produced when the package itself is a binary RPM and the fix
// applies via the upstream (source) package.
func TestMatcherRpm_DistroNotVulnerableIgnoreViaUpstream(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			// openssl-libs is owned by upstream openssl source RPM; both at fixed version
			pkgID := pkg.ID("openssl-libs-fixed")
			p := dbtest.NewPackage("openssl-libs", "1:1.1.1d-1.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.RHEL8).
				WithUpstream("openssl", "1:1.1.1d-1.el8").
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-2018-0735").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_UnaffectedRecordProducesIgnore verifies the explicit-Unaffected
// arm of the standard rpm matcher: when the DB carries an unaffected
// PackageHandle for the package (vunnel emits these for RHEL CVEs whose
// FixedIn entries all have Version="0", which the v6 OS transformer turns into
// db.UnaffectedPackageHandle rows), the matcher emits a "Distro Not Vulnerable"
// ignore for the package - distinct from the "package past fix" path covered
// by TestMatcherRpm_DistroNotVulnerableIgnore. CVE-1999-0199's only FixedIn is
// glibc Version="0".
func TestMatcherRpm_UnaffectedRecordProducesIgnore(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-1999-0199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("glibc-unaffected")
			p := dbtest.NewPackage("glibc", "2.28-100.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.RHEL8).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-1999-0199").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// A rhel:8 NAK (major-only, empty minor) must still apply to a rhel 8.4 scan:
// RHEL data lands at major granularity, so the major+empty-minor fallback in
// searchForOSExactVersions has to fire. Companion to
// SLES_RecordsDoNotCrossMinorVersion, which proves sibling minors don't leak.
func TestMatcherRpm_MajorOnlyUnaffectedRecordAppliesToMinorScan(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-1999-0199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("glibc-on-8.4")
			p := dbtest.NewPackage("glibc", "2.28-100.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(distro.New(distro.RedHat, "8.4", "")).
				Build()

			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-1999-0199").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_VulnerableAndUnaffectedInSameCall verifies that the standard
// matcher can produce a match and an Unaffected ignore for the same package
// in a single Match() call. CVE-2016-10228 has a real glibc fix at
// 0:2.28-151.el8, which the package version 2.28-100.el8 is below (vulnerable
// → match). CVE-1999-0199 has an Unaffected glibc record (FixedIn Version="0"
// → UnaffectedPackageHandle), which produces a "Distro Not Vulnerable" ignore
// in the same call. Selects both CVEs from the rhel8 fixture so the matcher
// sees the mixed shape.
func TestMatcherRpm_VulnerableAndUnaffectedInSameCall(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2016-10228", "rhel:8/cve-1999-0199").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			pkgID := pkg.ID("glibc-mixed")
			p := dbtest.NewPackage("glibc", "2.28-100.el8", syftPkg.RpmPkg).
				WithID(pkgID).
				WithDistro(dbtest.RHEL8).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2016-10228").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
			findings.Ignores().
				SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, "CVE-1999-0199").
				ForPackage(pkgID).
				WithRelationshipType(artifact.OwnershipByFileOverlapRelationship)
		})
}

// TestMatcherRpm_NoIgnoresWhenVulnerable verifies that a still-vulnerable
// package version produces a match and no ignore filters.
func TestMatcherRpm_NoIgnoresWhenVulnerable(t *testing.T) {
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2018-0735").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("openssl", "1:1.1.1a-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intPtr(1)}).
				Build()

			findings := db.Match(t, &matcher, p)
			findings.SelectMatch("CVE-2018-0735").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func Test_addEpochIfApplicable(t *testing.T) {
	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name: "assume 0 epoch",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
			},
			expected: "0:3.26.0-6.el8",
		},
		{
			name: "epoch already exists in version string",
			pkg: pkg.Package{
				Version: "7:3.26.0-6.el8",
			},
			expected: "7:3.26.0-6.el8",
		},
		{
			name: "epoch only exists in metadata",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
				Metadata: pkg.RpmMetadata{
					Epoch: intPtr(7),
				},
			},
			expected: "7:3.26.0-6.el8",
		},
		{
			name: "epoch does not exist in metadata",
			pkg: pkg.Package{
				Version: "3.26.0-6.el8",
				Metadata: pkg.RpmMetadata{
					Epoch: nil, // assume 0 epoch
				},
			},
			expected: "0:3.26.0-6.el8",
		},
		{
			name: "version is empty",
			pkg: pkg.Package{
				Version: "",
				Metadata: pkg.RpmMetadata{
					Epoch: nil, // assume 0 epoch
				},
			},
			expected: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := test.pkg
			addEpochIfApplicable(&p)
			assert.Equal(t, test.expected, p.Version)
		})
	}
}

// TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroEnabled exercises the EOL CPE
// fallback for an EOL distro (RHEL 7, EOL 2024-06-30) using real RHEL + EOL +
// NVD data. With UseCPEsForEOL=true, the matcher falls back to CPE matching
// via NVD since the distro is past EOL, so we expect both the rhel:7 distro
// disclosure AND the nvd CPE finding for the same CVE.
func TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroEnabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: true})

		// RHEL 7 (EOL'd 2024-06-30); openssl 1.1.0a CPE matches NVD CVE-2018-0735
		// (vulnerable range 1.1.0 - 1.1.0i)
		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "7", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		findings := db.Match(t, matcher, p)
		ms := findings.SelectMatches("CVE-2018-0735")
		ms.WithDetailType(match.CPEMatch).
			SelectDetailByCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			HasMatchType(match.CPEMatch)
		ms.WithDetailType(match.ExactDirectMatch).
			SelectDetailByDistro("redhat", "7").
			HasMatchType(match.ExactDirectMatch)
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroDisabled verifies the same EOL
// distro produces only the rhel:7 distro match (no CPE fallback) when
// UseCPEsForEOL=false.
func TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroDisabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: false})

		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "7", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		findings := db.Match(t, matcher, p)
		findings.SelectMatch("CVE-2018-0735").
			SelectDetailByDistro("redhat", "7").
			HasMatchType(match.ExactDirectMatch)
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_NoEOLData verifies that an unknown distro
// (no EOL record in the database) does not get the CPE fallback even when
// UseCPEsForEOL is enabled. With no rhel:9999 disclosures in the fixture and
// no EOL fallback, the matcher returns nothing.
func TestMatcherRpm_CPEFallbackWhenEOL_NoEOLData(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: true})

		// fake distro with no EOL data → fallback should not engage
		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "9999", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		db.Match(t, matcher, p).IsEmpty()
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_DistroNotEOL_FlagEnabled verifies that the
// CPE fallback does NOT engage when a known, NOT-yet-EOL distro is in use.
// The eol-rhel7 fixture also carries the real rhel:9 EOL record (eolFrom
// 2032-05-31), so RHEL 9 is a clean "we know about this distro and it's not
// EOL" case. With UseCPEsForEOL=true, the matcher must still skip CPE matching
// because the distro is supported. Combined with the absence of rhel:9
// disclosures in the fixture, we expect zero findings.
func TestMatcherRpm_CPEFallbackWhenEOL_DistroNotEOL_FlagEnabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: true})

		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(dbtest.RHEL9).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		db.Match(t, matcher, p).IsEmpty()
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_DistroNotEOL_FlagDisabled verifies that a
// not-EOL distro never gets CPE fallback when the flag is also disabled
// (the trivial baseline alongside FlagEnabled above).
func TestMatcherRpm_CPEFallbackWhenEOL_DistroNotEOL_FlagDisabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: false})

		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(dbtest.RHEL9).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		db.Match(t, matcher, p).IsEmpty()
	})
}
