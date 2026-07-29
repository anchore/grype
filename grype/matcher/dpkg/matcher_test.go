package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestMatcherDpkg_DirectMatch(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("debian:11/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			p := dbtest.NewPackage("openssl", "1.1.1k-1", syftPkg.DebPkg). // vulnerable (< 1.1.1w-0+deb11u2)
											WithDistro(dbtest.Debian11).
											Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherDpkg_DirectMatch_DHI(t *testing.T) {
	dbtest.DBs(t, "dhi-13").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := Matcher{}

		t.Run("affected DHI package matches", func(t *testing.T) {
			p := dbtest.NewPackage("coreutils", "9.7-3+dhi3", syftPkg.DebPkg).
				WithDistro(dbtest.DHI13).
				WithPURL("pkg:deb/dhi/coreutils@9.7-3%2Bdhi3?arch=arm64&distro=dhi-13").
				Build()

			db.Match(t, &matcher, p).
				SelectMatch("DHI-CVE-2017-18018-coreutils").
				SelectDetailByType(match.ExactDirectMatch).
				AsDistroSearch()
		})

		t.Run("fixed DHI package does not match", func(t *testing.T) {
			p := dbtest.NewPackage("coreutils", "9.7-3+dhi4", syftPkg.DebPkg).
				WithDistro(dbtest.DHI13).
				Build()
			db.Match(t, &matcher, p).Ignores().
				SelectRelatedPackageIgnores("DistroPackageFixed",
					"DHI-CVE-2017-18018-coreutils", "CVE-2017-18018")
		})

		t.Run("different DHI release is isolated", func(t *testing.T) {
			p := dbtest.NewPackage("coreutils", "9.7-3+dhi3", syftPkg.DebPkg).
				WithDistro(dbtest.DHI14).
				Build()
			db.Match(t, &matcher, p).IsEmpty()
		})

		t.Run("ordinary Debian is isolated", func(t *testing.T) {
			p := dbtest.NewPackage("coreutils", "9.7-3+dhi3", syftPkg.DebPkg).
				WithDistro(distro.New(distro.Debian, "13", "")).
				Build()
			db.Match(t, &matcher, p).IsEmpty()
		})
	})
}

func TestMatcherDpkg_IndirectMatch(t *testing.T) {
	dbtest.SharedDBs(t, "all").
		SelectOnly("debian:11/CVE-2024-0727").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := Matcher{}

			// binary package libssl3 with upstream openssl
			p := dbtest.NewPackage("libssl3", "1.1.1k-1", syftPkg.DebPkg). // vulnerable
											WithDistro(dbtest.Debian11).
											WithUpstream("openssl", "").
											Build()

			db.Match(t, &matcher, p).
				SelectMatch("CVE-2024-0727").
				SelectDetailByType(match.ExactIndirectMatch).
				AsDistroSearch()
		})
}

func TestMatcherDpkg_CPEFallbackWhenEOL(t *testing.T) {
	p := dbtest.NewPackage("openssl", "1.1.1k", syftPkg.DebPkg). // vulnerable
									WithDistro(dbtest.Debian8).
									WithCPE("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*").
									Build()

	tests := []struct {
		name             string
		useCPEsForEOL    bool
		expectCPEMatches bool
	}{
		{
			name:             "CPE fallback enabled and distro is EOL",
			useCPEsForEOL:    true,
			expectCPEMatches: true,
		},
		{
			name:             "CPE fallback disabled and distro is EOL",
			useCPEsForEOL:    false,
			expectCPEMatches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// use the local EOL fixture that has Debian 8 EOL date set
			dbtest.DBs(t, "eol-debian8").Run(func(t *testing.T, db *dbtest.DB) {
				matcher := NewDpkgMatcher(MatcherConfig{
					UseCPEsForEOL: tt.useCPEsForEOL,
				})

				findings := db.Match(t, matcher, p)

				if tt.expectCPEMatches {
					findings.
						ContainsVulnerabilities("CVE-2024-0727").
						SelectMatch("CVE-2024-0727").
						SelectDetailByType(match.CPEMatch).
						AsCPESearch().
						FoundCPEs("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
				} else {
					findings.IsEmpty()
				}
			})
		})
	}
}
