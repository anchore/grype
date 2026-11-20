package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/internal/ignorereasons"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The rapidfort-ubuntu fixture holds native ubuntu fixes in the channel-less rapidfort-ubuntu:20.04
// namespace and RapidFort-rebuild fixes in rapidfort-ubuntu:20.04+rf. Search rules add the rf channel
// for rf-versioned packages, searched in addition to the channel-less rows.
func TestRapidFortUbuntu_Matching(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortUbuntu, "20.04", "")

	// streamFinding is one expected finding for the test's CVE, identified by namespace
	type streamFinding struct {
		namespace string
		fixes     []string
	}

	tests := []struct {
		name        string
		pkgName     string
		pkgVersion  string
		d           *distro.Distro
		expectCVE   string
		expectState vulnerability.FixState
		expect      []streamFinding
		expectNone  bool
	}{
		{
			name:        "native package surfaces the native fix",
			pkgName:     "curl",
			pkgVersion:  "7.68.0-1ubuntu2.5",
			d:           rfDistro,
			expectCVE:   "CVE-2020-8169",
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-ubuntu:20.4", fixes: []string{"7.68.0-1ubuntu2.10"}},
			},
		},
		{
			name:       "plain ubuntu distro never sees rapidfort rows",
			pkgName:    "curl",
			pkgVersion: "7.68.0-1ubuntu2.5",
			d:          distro.New(distro.Ubuntu, "20.04", ""),
			expectNone: true,
		},
		{
			// both streams cover this version; the rf stream outranks the native row
			name:        "rf-versioned package surfaces the rf-stream fix, not the native one",
			pkgName:     "tar",
			pkgVersion:  "1.30+dfsg-7rfubu.1",
			d:           rfDistro,
			expectCVE:   "CVE-2022-48303",
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-ubuntu:20.4+rf", fixes: []string{"1.30+dfsg-8rfubu.1"}},
			},
		},
		{
			name:        "native-versioned package surfaces the native fix for a dual-stream CVE",
			pkgName:     "tar",
			pkgVersion:  "1.30+dfsg-7",
			d:           rfDistro,
			expectCVE:   "CVE-2022-48303",
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-ubuntu:20.4", fixes: []string{"1.30+dfsg-7ubuntu0.20.04.2"}},
			},
		},
		{
			// rf-named advisory files carry native events for stock builds; dpkg rules key on version only
			name:        "rf-named package with a stock version matches the native stream",
			pkgName:     "rf-wget",
			pkgVersion:  "1.20.3-1ubuntu2",
			d:           rfDistro,
			expectCVE:   "CVE-2021-31879",
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-ubuntu:20.4", fixes: []string{"1.20.3-1ubuntu3"}},
			},
		},
		{
			name:       "rapidfort distro with no data yields no matches",
			pkgName:    "curl",
			pkgVersion: "7.68.0-1ubuntu2.5",
			d:          distro.New(distro.RapidFortUbuntu, "22.04", ""),
			expectNone: true,
		},
	}

	dbtest.DBs(t, "rapidfort-ubuntu").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewDpkgMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				p := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.DebPkg).WithDistro(tt.d).Build()

				findings := db.Match(t, matcher, p)

				if tt.expectNone {
					findings.IsEmpty()
					return
				}

				matches := findings.SkipCompleteness().SelectMatches(tt.expectCVE).HasCount(len(tt.expect))
				for _, e := range tt.expect {
					sf := matches.WithNamespace(e.namespace)
					sf.HasMatchType(match.ExactDirectMatch)
					sf.HasFix(tt.expectState, e.fixes...)
				}
			})
		}
	})
}

// CVE-2026-11111 is recorded twice for openssl: the channel-less rapidfort-ubuntu:20.04 row has an
// open-ended `>= 1.1.1-1ubuntu2` range with no fix, and the rapidfort-ubuntu:20.04+rf row has the
// rebuild's fix at 1.1.1-3rfubu.1. The rf row must resolve the native disclosure for rf builds.
func TestRapidFortUbuntu_StreamFixResolvesNativeDisclosure(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortUbuntu, "20.04", "")

	dbtest.DBs(t, "rapidfort-ubuntu").
		SelectOnly("CVE-2026-11111").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewDpkgMatcher(MatcherConfig{})

			t.Run("rebuild past its stream fix is resolved despite the open-ended native row", func(t *testing.T) {
				pkgID := pkg.ID("openssl-past-rf-fix")
				p := dbtest.NewPackage("openssl", "1.1.1-5rfubu.1", syftPkg.DebPkg).
					WithID(pkgID).
					WithDistro(rfDistro).
					Build()

				// the resolved CVE becomes a distro-fixed ownership ignore
				findings := db.Match(t, matcher, p)
				findings.OnlyHasVulnerabilities()
				findings.Ignores().
					SelectRelatedPackageIgnores(ignorereasons.DistroFixed, "CVE-2026-11111").
					ForPackage(pkgID)
			})

			// an rf build below the native row's lower bound; the rf row covers it
			t.Run("a native row that does not cover this build does not resolve anything", func(t *testing.T) {
				p := dbtest.NewPackage("openssl", "1.1.1-0rfubu.1", syftPkg.DebPkg).WithDistro(rfDistro).Build()

				db.Match(t, matcher, p).
					SkipCompleteness().
					SelectMatches("CVE-2026-11111").
					HasCount(1).
					WithNamespace("rapidfort:distro:rapidfort-ubuntu:20.4+rf").
					HasFix(vulnerability.FixStateFixed, "1.1.1-3rfubu.1")
			})

			// both rows cover this build; the native row has no fix and the rf row names one
			t.Run("rebuild below its stream fix is reported once, with the fix", func(t *testing.T) {
				p := dbtest.NewPackage("openssl", "1.1.1-2rfubu.1", syftPkg.DebPkg).WithDistro(rfDistro).Build()

				db.Match(t, matcher, p).
					SkipCompleteness().
					SelectMatches("CVE-2026-11111").
					HasCount(1).
					WithNamespace("rapidfort:distro:rapidfort-ubuntu:20.4+rf").
					HasFix(vulnerability.FixStateFixed, "1.1.1-3rfubu.1")
			})
		})
}
