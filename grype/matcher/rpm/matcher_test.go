package rpm

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/testdb"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftCpe "github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherRpm(t *testing.T) {
	// Uses real RHEL fixture for CVE-2015-20107 (python3 fixed at 0:3.6.8-47.el8_6,
	// python38 with module python38:3.8, python39 with module python39:3.9).
	provider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("rhel-8-cve-2015-20107.json")),
	)

	tests := []struct {
		name            string
		p               pkg.Package
		distro          *distro.Distro
		matcher         Matcher
		expectedMatches map[string]match.Type
	}{
		{
			name: "Rpm Match matches by direct and by source indirection",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python3-libs",
				Version: "3.6.8-37.el8",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "python3",
						Version: "3.6.8-37.el8",
					},
				},
			},
			distro:  distro.New(distro.CentOS, "8", ""),
			matcher: Matcher{},
			expectedMatches: map[string]match.Type{
				"CVE-2015-20107": match.ExactIndirectMatch,
			},
		},
		{
			name: "Rpm Match matches by direct when package name is the vulnerable package",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python3",
				Version: "3.6.8-37.el8",
				Type:    syftPkg.RpmPkg,
			},
			distro:  distro.New(distro.RedHat, "8", ""),
			matcher: Matcher{},
			expectedMatches: map[string]match.Type{
				"CVE-2015-20107": match.ExactDirectMatch,
			},
		},
		{
			name: "Rpm Match - no match when version is at fix",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python3",
				Version: "3.6.8-47.el8_6",
				Type:    syftPkg.RpmPkg,
			},
			distro:          distro.New(distro.RedHat, "8", ""),
			matcher:         Matcher{},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "Rpm Match - desynced source version above fix means no indirect match",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python3-libs",
				Version: "3.6.8-37.el8",
				Type:    syftPkg.RpmPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name:    "python3",
						Version: "3.6.8-50.el8",
					},
				},
			},
			distro:          distro.New(distro.RedHat, "8", ""),
			matcher:         Matcher{},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "package with modularity label matching module in fixture",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python38",
				Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("python38:3.8:1234:5678"),
				},
			},
			distro:  distro.New(distro.RedHat, "8", ""),
			matcher: Matcher{},
			expectedMatches: map[string]match.Type{
				"CVE-2015-20107": match.ExactDirectMatch,
			},
		},
		{
			name: "package with non-matching modularity label",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python38",
				Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					ModularityLabel: strRef("python39:3.9:1234:5678"),
				},
			},
			distro:          distro.New(distro.RedHat, "8", ""),
			matcher:         Matcher{},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "package without modularity label matches all entries",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "python38",
				Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
				Type:    syftPkg.RpmPkg,
			},
			distro:  distro.New(distro.RedHat, "8", ""),
			matcher: Matcher{},
			expectedMatches: map[string]match.Type{
				"CVE-2015-20107": match.ExactDirectMatch,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.p.Distro = test.distro
			actual, _, err := test.matcher.Match(provider, test.p)
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
					assert.Equal(t, test.matcher.Type(), detail.Matcher, "failed to capture matcher type")
				}
			}

			if t.Failed() {
				t.Logf("discovered CVES: %+v", actual)
			}
		})
	}
}

func TestMatcherRpm_Epoch(t *testing.T) {
	// Uses real RHEL fixture for CVE-2018-0734 (openssl fixed at 1:1.1.1c-2.el8, epoch 1).
	provider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("rhel-8-cve-2018-0734.json")),
	)

	matcher := Matcher{}
	d := distro.New(distro.RedHat, "8", "")

	tests := []struct {
		name        string
		p           pkg.Package
		expectMatch bool
	}{
		{
			name: "package without epoch assumed 0 - vulnerable when fix has epoch 1",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1.1.1-1.el8",
				Type:    syftPkg.RpmPkg,
			},
			expectMatch: true,
		},
		{
			name: "package without epoch is assumed to be 0 - compared against vuln WITH epoch",
			p: pkg.Package{
				ID:       pkg.ID(uuid.NewString()),
				Name:     "openssl",
				Version:  "1.1.1-1.el8",
				Type:     syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{},
			},
			expectMatch: true,
		},
		{
			name: "package with epoch 1 at fix version - not vulnerable",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1:1.1.1c-2.el8",
				Type:    syftPkg.RpmPkg,
			},
			expectMatch: false,
		},
		{
			name: "package with epoch 1 above fix - not vulnerable",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1:1.1.1k-5.el8",
				Type:    syftPkg.RpmPkg,
			},
			expectMatch: false,
		},
		{
			name: "package WITH higher epoch 2 - not vulnerable",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "2:0.9.8-1.el8",
				Type:    syftPkg.RpmPkg,
			},
			expectMatch: false,
		},
		{
			name: "package with epoch 1 below fix - vulnerable",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1:1.0.2k-16.el8",
				Type:    syftPkg.RpmPkg,
			},
			expectMatch: true,
		},
		{
			name: "epoch from metadata when not in version string",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1.0.2k-16.el8",
				Type:    syftPkg.RpmPkg,
				Metadata: pkg.RpmMetadata{
					Epoch: intRef(1),
				},
			},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Distro = d
			actual, _, err := matcher.Match(provider, tt.p)
			require.NoError(t, err)

			cveMatches := filterByVulnID(actual, "CVE-2018-0734")
			if tt.expectMatch {
				require.NotEmpty(t, cveMatches, "expected match for CVE-2018-0734")
			} else {
				assert.Empty(t, cveMatches, "expected no match for CVE-2018-0734")
			}
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
	// CPE fallback behavior: when a distro is past its EOL date and the
	// UseCPEsForEOL config flag is set, the matcher also performs CPE-based
	// matching in addition to distro-based matching.
	//
	// Uses real fixtures:
	// - RHEL 7 (EOL 2024-06-30, past) with CVE-2018-0734 openssl vulnerability
	// - RHEL 9 (EOL 2032-05-31, future) with a vulnerability to create the OS row
	// - NVD CVE-2018-0734 with openssl CPE data for CPE-based matching
	// - EOL fixtures for RHEL 7 and RHEL 9

	// Provider for EOL distro (RHEL 7)
	eolProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("rhel-7-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("nvd-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("eol-rhel-7.json")),
	)

	// Provider for not-EOL distro (RHEL 9)
	notEolProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("rhel-9-cve-2005-2541.json")),
		testdb.WithVunnelFixture(testdb.Fixture("nvd-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("eol-rhel-9.json")),
	)

	// Provider with no EOL data at all (RHEL 8 vuln but no EOL fixture)
	noEolDataProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("rhel-8-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("nvd-cve-2018-0734.json")),
	)

	tests := []struct {
		name             string
		provider         vulnerability.Provider
		distro           *distro.Distro
		useCPEsForEOL    bool
		expectCPEMatches bool
	}{
		{
			name:             "CPE fallback enabled and distro is EOL - should include CPE matches",
			provider:         eolProvider,
			distro:           distro.New(distro.RedHat, "7", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: true,
		},
		{
			name:             "CPE fallback enabled but distro not EOL - should not include CPE matches",
			provider:         notEolProvider,
			distro:           distro.New(distro.RedHat, "9", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro is EOL - should not include CPE matches",
			provider:         eolProvider,
			distro:           distro.New(distro.RedHat, "7", ""),
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro not EOL - should not include CPE matches",
			provider:         notEolProvider,
			distro:           distro.New(distro.RedHat, "9", ""),
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback enabled but no EOL data - should not include CPE matches",
			provider:         noEolDataProvider,
			distro:           distro.New(distro.RedHat, "8", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewRpmMatcher(MatcherConfig{
				UseCPEsForEOL: tt.useCPEsForEOL,
			})

			p := pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1.0.2a",
				Type:    syftPkg.RpmPkg,
				Distro:  tt.distro,
				CPEs: []syftCpe.CPE{
					syftCpe.Must("cpe:2.3:a:openssl:openssl:1.0.2a:*:*:*:*:*:*:*", ""),
				},
			}

			matches, _, err := matcher.Match(tt.provider, p)
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

func filterByVulnID(matches []match.Match, id string) []match.Match {
	var result []match.Match
	for _, m := range matches {
		if m.Vulnerability.ID == id {
			result = append(result, m)
		}
	}
	return result
}
