package rpm

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/syft/syft/artifact"
	syftCpe "github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpm_DirectMatch(t *testing.T) {
	dbtest.DBs(t, "rhel8-real").
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
	dbtest.DBs(t, "rhel8-real").
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
	dbtest.DBs(t, "rhel8-real").
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
	dbtest.DBs(t, "rhel8-real").
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
	dbtest.DBs(t, "rhel8-real").
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
	dbtest.DBs(t, "rhel8-real").
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

// TestMatcherRpm_IgnoreFilters exercises specific ignore-filter behavior.
// These tests use precisely shaped vulnerability records to verify each path
// in the ignore-filter logic; mock vulnerabilities are easier to control here
// than scrubbing real records for matching shapes.
func TestMatcherRpm_IgnoreFilters(t *testing.T) {
	d := distro.New(distro.RedHat, "8", "")
	tests := []struct {
		name            string
		p               pkg.Package
		vulns           []vulnerability.Vulnerability
		expectedIgnores []match.IgnoreFilter
	}{
		{
			name: "direct match not vulnerable produces Distro Not Vulnerable ignore",
			p: pkg.Package{
				ID:      pkg.ID("httpd-fixed"),
				Name:    "httpd",
				Version: "2.4.37-51.el8",
				Type:    syftPkg.RpmPkg,
			},
			vulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference:   vulnerability.Reference{ID: "CVE-2023-1234", Namespace: "redhat:distro:redhat:8"},
					Constraint:  version.MustGetConstraint("< 0:2.4.37-50.el8", version.RpmFormat),
				},
			},
			// pkg version 51 > fix 50 → not vulnerable → ignore
			expectedIgnores: []match.IgnoreFilter{
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2023-1234",
					RelatedPackageID: pkg.ID("httpd-fixed"),
				},
			},
		},
		{
			name: "upstream not vulnerable produces ignore",
			p: pkg.Package{
				ID:      pkg.ID("neutron-libs-fixed"),
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "7.1.3-6.el8",
					},
				},
			},
			vulns: []vulnerability.Vulnerability{
				{
					// upstream vuln where pkg version is NOT vulnerable (7.1.3-6 >= 7.0.4-1)
					PackageName: "neutron",
					Reference:   vulnerability.Reference{ID: "CVE-2013-old", Namespace: "redhat:distro:redhat:8"},
					Constraint:  version.MustGetConstraint("< 7.0.4-1", version.RpmFormat),
				},
			},
			expectedIgnores: []match.IgnoreFilter{
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2013-old",
					RelatedPackageID: pkg.ID("neutron-libs-fixed"),
				},
			},
		},
		{
			name: "no ignores when all vulns are vulnerable",
			p: pkg.Package{
				ID:      pkg.ID("httpd-vuln"),
				Name:    "httpd",
				Version: "2.4.37-10.el8",
				Type:    syftPkg.RpmPkg,
			},
			vulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference:   vulnerability.Reference{ID: "CVE-2023-1234", Namespace: "redhat:distro:redhat:8"},
					Constraint:  version.MustGetConstraint("< 0:2.4.37-50.el8", version.RpmFormat),
				},
			},
			// pkg version 10 < 50 → vulnerable → no ignores
			expectedIgnores: nil,
		},
		{
			name: "unaffected record produces ignore",
			p: pkg.Package{
				ID:      pkg.ID("httpd-unaffected"),
				Name:    "httpd",
				Version: "2.4.37-51.el8",
				Type:    syftPkg.RpmPkg,
			},
			vulns: []vulnerability.Vulnerability{
				{
					PackageName: "httpd",
					Reference:   vulnerability.Reference{ID: "CVE-2023-1234", Namespace: "redhat:distro:redhat:8"},
					Constraint:  version.MustGetConstraint("< 0:2.4.37-50.el8", version.RpmFormat),
				},
				{
					// unaffected record: pkg version 51 satisfies ">= 2.4.37-51.el8" → ignored
					PackageName: "httpd",
					Reference:   vulnerability.Reference{ID: "CVE-2023-5678", Namespace: "redhat:distro:redhat:8"},
					Constraint:  version.MustGetConstraint(">= 0:2.4.37-51.el8", version.RpmFormat),
					Unaffected:  true,
				},
			},
			expectedIgnores: []match.IgnoreFilter{
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2023-1234",
					RelatedPackageID: pkg.ID("httpd-unaffected"),
				},
				match.IgnoreRelatedPackage{
					Reason:           "Distro Not Vulnerable",
					RelationshipType: artifact.OwnershipByFileOverlapRelationship,
					VulnerabilityID:  "CVE-2023-5678",
					RelatedPackageID: pkg.ID("httpd-unaffected"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Distro = d
			store := mock.VulnerabilityProvider(tt.vulns...)
			matcher := Matcher{}

			_, ignores, err := matcher.Match(store, tt.p)
			require.NoError(t, err)

			require.ElementsMatch(t, tt.expectedIgnores, ignores)
		})
	}
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

func TestMatcherRpm_CPEFallbackWhenEOL(t *testing.T) {
	pastEOL := time.Now().AddDate(-1, 0, 0)  // 1 year ago
	futureEOL := time.Now().AddDate(1, 0, 0) // 1 year from now

	d := distro.New(distro.CentOS, "8", "")

	// package with CPEs for CPE-based matching
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "openssl",
		Version: "1.0.1",
		Type:    syftPkg.RpmPkg,
		Distro:  d,
		CPEs: []syftCpe.CPE{
			syftCpe.Must("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*", ""),
		},
	}

	tests := []struct {
		name             string
		useCPEsForEOL    bool
		eolDate          *time.Time
		expectCPEMatches bool
	}{
		{
			name:             "CPE fallback enabled and distro is EOL - should include CPE matches",
			useCPEsForEOL:    true,
			eolDate:          &pastEOL,
			expectCPEMatches: true,
		},
		{
			name:             "CPE fallback enabled but distro not EOL - should not include CPE matches",
			useCPEsForEOL:    true,
			eolDate:          &futureEOL,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro is EOL - should not include CPE matches",
			useCPEsForEOL:    false,
			eolDate:          &pastEOL,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro not EOL - should not include CPE matches",
			useCPEsForEOL:    false,
			eolDate:          &futureEOL,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback enabled but no EOL data - should not include CPE matches",
			useCPEsForEOL:    true,
			eolDate:          nil,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewRpmMatcher(MatcherConfig{
				UseCPEsForEOL: tt.useCPEsForEOL,
			})

			vp := newMockEOLProvider(tt.eolDate)
			matches, _, err := matcher.Match(vp, p)
			require.NoError(t, err)

			// check if any CPE matches were found
			hasCPEMatch := false
			for _, m := range matches {
				for _, detail := range m.Details {
					if detail.Type == match.CPEMatch {
						hasCPEMatch = true
						break
					}
				}
			}

			if tt.expectCPEMatches {
				assert.True(t, hasCPEMatch, "expected CPE matches for EOL distro")
			} else {
				assert.False(t, hasCPEMatch, "did not expect CPE matches")
			}
		})
	}
}
