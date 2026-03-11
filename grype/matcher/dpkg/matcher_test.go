package dpkg

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

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	// Uses real Debian fixture for CVE-2014-0071 (neutron fixed at 2014.1-1 on debian:8).
	provider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("debian-8-cve-2014-0071.json")),
	)

	matcher := Matcher{}
	d := distro.New(distro.Debian, "8", "")

	tests := []struct {
		name            string
		p               pkg.Package
		expectedMatches map[string]match.Type
	}{
		{
			name: "binary package matches via upstream source indirection",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron-common",
				Version: "2014.0.1-1",
				Type:    syftPkg.DebPkg,
				Upstreams: []pkg.UpstreamPackage{
					{
						Name: "neutron",
					},
				},
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-0071": match.ExactIndirectMatch,
			},
		},
		{
			name: "direct match when package name is the vulnerable package",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron",
				Version: "2014.0.1-1",
				Type:    syftPkg.DebPkg,
			},
			expectedMatches: map[string]match.Type{
				"CVE-2014-0071": match.ExactDirectMatch,
			},
		},
		{
			name: "no match when version is at fix",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron",
				Version: "2014.1-1",
				Type:    syftPkg.DebPkg,
			},
			expectedMatches: map[string]match.Type{},
		},
		{
			name: "no match when version is above fix",
			p: pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "neutron",
				Version: "2015.0.0-1",
				Type:    syftPkg.DebPkg,
			},
			expectedMatches: map[string]match.Type{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.Distro = d
			actual, _, err := matcher.Match(provider, tt.p)
			require.NoError(t, err)

			assert.Len(t, actual, len(tt.expectedMatches), "unexpected matches count")

			for _, a := range actual {
				expectedType, ok := tt.expectedMatches[a.Vulnerability.ID]
				if !ok {
					t.Errorf("unexpected match CVE: %s", a.Vulnerability.ID)
					continue
				}
				require.NotEmpty(t, a.Details)
				for _, de := range a.Details {
					assert.Equal(t, expectedType, de.Type)
					assert.Equal(t, matcher.Type(), de.Matcher, "failed to capture matcher type")
				}
				assert.Equal(t, tt.p.Name, a.Package.Name, "failed to capture original package name")
			}

			if t.Failed() {
				t.Logf("discovered matches: %+v", actual)
			}
		})
	}
}

func TestMatcherDpkg_CPEFallbackWhenEOL(t *testing.T) {
	// CPE fallback behavior: when a distro is past its EOL date and the
	// UseCPEsForEOL config flag is set, the matcher also performs CPE-based
	// matching in addition to distro-based matching.
	//
	// Uses real fixtures:
	// - Debian 8 (EOL 2018-06-17, past) with CVE-2014-0071 vulnerability
	// - Ubuntu 24.04 (EOL 2029-05-31, future) with CVE-2024-0567 vulnerability
	// - NVD CVE-2018-0734 with openssl CPE data for CPE-based matching
	// - EOL fixtures for Debian 8 and Ubuntu 24.04

	// Provider for EOL distro (Debian 8)
	eolProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("debian-8-cve-2014-0071.json")),
		testdb.WithVunnelFixture(testdb.Fixture("nvd-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("eol-debian-8.json")),
	)

	// Provider for not-EOL distro (Ubuntu 24.04)
	notEolProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("ubuntu-24.04-cve-2024-0567.json")),
		testdb.WithVunnelFixture(testdb.Fixture("nvd-cve-2018-0734.json")),
		testdb.WithVunnelFixture(testdb.Fixture("eol-ubuntu-24.04.json")),
	)

	// Provider with no EOL data at all (Debian 8 vuln but no EOL fixture)
	noEolDataProvider := testdb.New(t,
		testdb.WithVunnelFixture(testdb.Fixture("debian-8-cve-2014-0071.json")),
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
			distro:           distro.New(distro.Debian, "8", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: true,
		},
		{
			name:             "CPE fallback enabled but distro not EOL - should not include CPE matches",
			provider:         notEolProvider,
			distro:           distro.New(distro.Ubuntu, "24.04", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro is EOL - should not include CPE matches",
			provider:         eolProvider,
			distro:           distro.New(distro.Debian, "8", ""),
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback disabled and distro not EOL - should not include CPE matches",
			provider:         notEolProvider,
			distro:           distro.New(distro.Ubuntu, "24.04", ""),
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
		{
			name:             "CPE fallback enabled but no EOL data - should not include CPE matches",
			provider:         noEolDataProvider,
			distro:           distro.New(distro.Debian, "8", ""),
			useCPEsForEOL:    true,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := NewDpkgMatcher(MatcherConfig{
				UseCPEsForEOL: tt.useCPEsForEOL,
			})

			p := pkg.Package{
				ID:      pkg.ID(uuid.NewString()),
				Name:    "openssl",
				Version: "1.0.2a-1",
				Type:    syftPkg.DebPkg,
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
