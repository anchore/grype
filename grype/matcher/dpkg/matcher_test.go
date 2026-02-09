package dpkg

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/grype/internal/stringutil"
	syftCpe "github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_matchBySourceIndirection(t *testing.T) {
	matcher := Matcher{}

	d := distro.New(distro.Debian, "8", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "neutron",
		Version: "2014.1.3-6",
		Type:    syftPkg.DebPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "neutron-devel",
			},
		},
	}

	vp := newMockProvider()
	actual, err := matcher.matchUpstreamPackages(vp, p)
	assert.NoError(t, err, "unexpected err from matchUpstreamPackages", err)

	assert.Len(t, actual, 2, "unexpected indirect matches count")

	foundCVEs := stringutil.NewStringSet()
	for _, a := range actual {
		foundCVEs.Add(a.Vulnerability.ID)

		require.NotEmpty(t, a.Details)
		for _, d := range a.Details {
			assert.Equal(t, match.ExactIndirectMatch, d.Type, "indirect match not indicated")
		}
		assert.Equal(t, p.Name, a.Package.Name, "failed to capture original package name")
		for _, detail := range a.Details {
			assert.Equal(t, matcher.Type(), detail.Matcher, "failed to capture matcher type")
		}
	}

	for _, id := range []string{"CVE-2014-fake-2", "CVE-2013-fake-3"} {
		if !foundCVEs.Contains(id) {
			t.Errorf("missing discovered CVE: %s", id)
		}
	}
	if t.Failed() {
		t.Logf("discovered CVES: %+v", foundCVEs)
	}
}

func TestMatcherDpkg_CPEFallbackWhenEOL(t *testing.T) {
	pastEOL := time.Now().AddDate(-1, 0, 0)  // 1 year ago
	futureEOL := time.Now().AddDate(1, 0, 0) // 1 year from now

	d := distro.New(distro.Debian, "8", "")

	// package with CPEs for CPE-based matching
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "openssl",
		Version: "1.0.1",
		Type:    syftPkg.DebPkg,
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
			matcher := NewDpkgMatcher(MatcherConfig{
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

// TestMatcherDpkg_RealDB_DirectMatch tests the dpkg matcher with direct package
// matching using a real database built from vunnel provider fixtures.
func TestMatcherDpkg_RealDB_DirectMatch(t *testing.T) {
	dbtest.DBs(t, "dpkg-fixture").Run(func(t *testing.T, db *dbtest.DB) {
		// neutron 2014.1.3-5 is vulnerable to CVE-2014-fake-1 (fixed in 2014.1.3-6)
		p := dbtest.NewPackage("neutron", "2014.1.3-5", syftPkg.DebPkg).
			WithDistro(dbtest.Debian8).
			Build()

		actual := db.MustMatch(t, &Matcher{}, p)

		dbtest.AssertMatchVulnerabilityIDs(t, actual, "CVE-2014-fake-1")

		require.Len(t, actual, 1)
		dbtest.AssertMatch(t, actual[0]).
			HasVulnerabilityID("CVE-2014-fake-1").
			HasPackageName("neutron")
	})
}

// TestMatcherDpkg_RealDB_NoMatchWhenFixed tests that a fixed version does not match.
func TestMatcherDpkg_RealDB_NoMatchWhenFixed(t *testing.T) {
	dbtest.DBs(t, "dpkg-fixture").Run(func(t *testing.T, db *dbtest.DB) {
		// neutron 2014.1.3-6 is the fixed version, should not match
		p := dbtest.NewPackage("neutron", "2014.1.3-6", syftPkg.DebPkg).
			WithDistro(dbtest.Debian8).
			Build()

		actual := db.MustMatch(t, &Matcher{}, p)

		dbtest.AssertNoMatches(t, actual)
	})
}

// TestMatcherDpkg_RealDB_IndirectMatch tests the dpkg matcher with upstream/indirect
// package matching using a real database.
func TestMatcherDpkg_RealDB_IndirectMatch(t *testing.T) {
	dbtest.DBs(t, "dpkg-fixture").Run(func(t *testing.T, db *dbtest.DB) {
		// neutron with upstream neutron-devel should match CVE-2014-fake-2 and CVE-2013-fake-3
		// but NOT CVE-2013-fake-BAD (version constraint too old)
		p := dbtest.NewPackage("neutron", "2014.1.3-6", syftPkg.DebPkg).
			WithDistro(dbtest.Debian8).
			WithUpstream("neutron-devel", "").
			Build()

		actual := db.MustMatch(t, &Matcher{}, p)

		// should match the two upstream vulnerabilities
		dbtest.AssertMatchCount(t, actual, 2)
		dbtest.AssertMatchVulnerabilityIDs(t, actual, "CVE-2014-fake-2", "CVE-2013-fake-3")

		// verify all matches are indirect
		for _, m := range actual {
			require.NotEmpty(t, m.Details)
			for _, d := range m.Details {
				assert.Equal(t, match.ExactIndirectMatch, d.Type, "expected indirect match type")
			}
		}
	})
}
