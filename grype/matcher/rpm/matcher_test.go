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
	"github.com/anchore/syft/syft/artifact"
	syftCpe "github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpm(t *testing.T) {
	tests := []struct {
		name            string
		p               pkg.Package
		setup           func() (vulnerability.Provider, *distro.Distro, Matcher)
		expectedMatches map[string]match.Type
		wantErr         bool
	}{
		{
			name: "Rpm Match matches by direct and by source indirection",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
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
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")
				store := newMockProvider("neutron-libs", "neutron", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
				"CVE-2014-fake-2": match.ExactIndirectMatch,
				"CVE-2013-fake-3": match.ExactIndirectMatch,
			},
		},
		{
			name: "Rpm Match matches by direct and ignores the source rpm when the package names are the same",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "7.1.3-6.el8",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("neutron", "neutron-devel", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Regression against https://github.com/anchore/grype/issues/376
			name: "Rpm Match matches by direct and by source indirection when the SourceRpm version is desynced from package version",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron-libs",
				Version: "7.1.3-6",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "neutron",
						Version: "17.16.3-229.el8",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("neutron-libs", "neutron", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			// Epoch in pkg but not in src package version, epoch found in the vuln record
			// Regression: https://github.com/anchore/grype/issues/437
			name: "Rpm Match should not occur due to source match even though source has no epoch",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "perl-Errno",
				Version: "0:1.28-419.el8_4.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					Epoch: intRef(0),
				},
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "perl",
						Version: "5.26.3-419.el8_4.1",
					},
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("perl-Errno", "perl", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-2": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactIndirectMatch,
			},
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln with NO epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("perl-Errno", "doesn't-matter", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("perl-Errno", "doesn't-matter", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-2": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln with NO epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("perl-Errno", "doesn't-matter", false, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-fake-1": match.ExactDirectMatch,
			},
		},
		{
			name: "package WITH epoch - compared against vuln WITH epoch (direct match only)",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "perl-Errno",
				Version:  "2:1.28-419.el8_4.1",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("perl-Errno", "doesn't-matter", true, false)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "package with modularity label 1",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("containertools:3:1234:5678"),
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-1": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactDirectMatch,
			},
		},
		{
			name: "package with modularity label 2",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("containertools:1:abc:123"),
				},
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-3": match.ExactDirectMatch,
			},
		},
		{
			name: "package without modularity label",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "maniac",
				Version: "0.1",
				Type:    syftPkg.RpmPkg,
			},
			setup: func() (vulnerability.Provider, *distro.Distro, Matcher) {
				matcher := Matcher{}
				d := distro.New(distro.CentOS, "8", "")

				store := newMockProvider("maniac", "doesn't-matter", false, true)

				return store, d, matcher
			},
			expectedMatches: map[string]match.Type{
				"CVE-2021-1": match.ExactDirectMatch,
				"CVE-2021-2": match.ExactDirectMatch,
				"CVE-2021-3": match.ExactDirectMatch,
				"CVE-2021-4": match.ExactDirectMatch,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, d, matcher := test.setup()
			if test.p.Distro == nil {
				test.p.Distro = d
			}
			actual, _, err := matcher.Match(store, test.p)
			if err != nil {
				t.Fatal("could not find match: ", err)
			}

			assert.Len(t, actual, len(test.expectedMatches), "unexpected matches count")

			for _, a := range actual {
				if val, ok := test.expectedMatches[a.Vulnerability.ID]; !ok {
					t.Errorf("return unknown match CVE: %s", a.Vulnerability.ID)
					continue
				} else {
					require.NotEmpty(t, a.Details)
					for _, de := range a.Details {
						assert.Equal(t, val, de.Type)
					}
				}

				assert.Equal(t, test.p.Name, a.Package.Name, "failed to capture original package name")
				for _, detail := range a.Details {
					assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
				}
			}

			if t.Failed() {
				t.Logf("discovered CVES: %+v", actual)
			}
		})
	}
}

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
