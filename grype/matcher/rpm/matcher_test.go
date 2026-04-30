package rpm

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
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
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
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
			// version newer than fix - not vulnerable
			p := dbtest.NewPackage("openssl", "1:1.1.1c-2.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
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
					Epoch:           intRef(0),
					ModularityLabel: strRef("httpd:2.4:1234:5678"),
				}).
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
					Epoch:           intRef(0),
					ModularityLabel: strRef("httpd:2.6:1234:5678"),
				}).
				Build()

			db.Match(t, &matcher, p).IsEmpty()
		})
}

func TestMatcherRpm_PackageWithoutEpochAssumesZero(t *testing.T) {
	// glibc fix is "0:2.28-151.el8"; package has no epoch metadata,
	// so the matcher should treat it as epoch 0
	dbtest.DBs(t, "rhel8").
		SelectOnly("rhel:8/cve-2016-10228").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}
			p := dbtest.NewPackage("glibc", "2.28-100.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2016-10228").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
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
			pkgID := pkg.ID(uuid.NewString())
			p := dbtest.NewPackage("openssl", "1:1.1.1d-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
				Build()
			p.ID = pkgID

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.Empty(t, matches, "fixed package should not produce matches")

			require.ElementsMatch(t, []match.IgnoreFilter{
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2018-0735",
					RelatedPackageID: pkgID,
				},
			}, ignores)
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
			pkgID := pkg.ID(uuid.NewString())
			p := dbtest.NewPackage("openssl-libs", "1:1.1.1d-1.el8", syftPkg.RpmPkg).
				WithDistro(dbtest.RHEL8).
				WithUpstream("openssl", "1:1.1.1d-1.el8").
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
				Build()
			p.ID = pkgID

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.Empty(t, matches, "fixed upstream should not produce matches")

			require.ElementsMatch(t, []match.IgnoreFilter{
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2018-0735",
					RelatedPackageID: pkgID,
				},
			}, ignores)
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
				WithMetadata(pkg.RpmMetadata{Epoch: intRef(1)}).
				Build()

			matches, ignores, err := matcher.Match(db, p)
			require.NoError(t, err)
			require.NotEmpty(t, matches, "vulnerable package should produce a match")
			require.Empty(t, ignores, "vulnerable package should not produce ignore filters")
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
					Epoch: intRef(7),
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
// via NVD since the distro is past EOL.
func TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroEnabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: true})

		// RHEL 7 (EOL'd 2024-06-30); openssl 1.1.0a CPE matches NVD CVE-2018-0735
		// (vulnerable range 1.1.0 - 1.1.0i)
		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "7", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		matches, _, err := matcher.Match(db, p)
		require.NoError(t, err)

		hasCPEMatch := false
		for _, m := range matches {
			for _, detail := range m.Details {
				if detail.Type == match.CPEMatch {
					hasCPEMatch = true
				}
			}
		}
		assert.True(t, hasCPEMatch, "expected CPE matches for EOL distro when fallback enabled")
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroDisabled verifies the same EOL
// distro produces NO CPE matches when UseCPEsForEOL=false.
func TestMatcherRpm_CPEFallbackWhenEOL_EOLDistroDisabled(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: false})

		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "7", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		matches, _, err := matcher.Match(db, p)
		require.NoError(t, err)

		for _, m := range matches {
			for _, detail := range m.Details {
				assert.NotEqual(t, match.CPEMatch, detail.Type,
					"did not expect CPE match when fallback disabled")
			}
		}
	})
}

// TestMatcherRpm_CPEFallbackWhenEOL_NoEOLData verifies that an unknown distro
// (no EOL record in the database) does not get the CPE fallback even when
// UseCPEsForEOL is enabled.
func TestMatcherRpm_CPEFallbackWhenEOL_NoEOLData(t *testing.T) {
	dbtest.DBs(t, "eol-rhel7").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{UseCPEsForEOL: true})

		// fake distro with no EOL data → fallback should not engage
		p := dbtest.NewPackage("openssl", "1.1.0a", syftPkg.RpmPkg).
			WithDistro(distro.New(distro.RedHat, "9999", "")).
			WithCPE("cpe:2.3:a:openssl:openssl:1.1.0a:*:*:*:*:*:*:*").
			Build()

		matches, _, err := matcher.Match(db, p)
		require.NoError(t, err)

		for _, m := range matches {
			for _, detail := range m.Details {
				assert.NotEqual(t, match.CPEMatch, detail.Type,
					"did not expect CPE match when no EOL data is available")
			}
		}
	})
}
