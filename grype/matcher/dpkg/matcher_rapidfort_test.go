package dpkg

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The rapidfort-ubuntu fixture carries curated advisories under the rapidfort-ubuntu OS name:
// native ubuntu-stream fixes live in the channel-less rapidfort-ubuntu:20.04 namespace and
// RapidFort-rebuild fixes live in the rapidfort-ubuntu:20.04+rf channel. The stock dpkg matcher
// (no rapidfort-specific matcher) resolves these through the source-metadata distro identifier
// (which produces the rapidfort-ubuntu distro) and the per-package OS routing rules (which add
// the +rf channel for rf-marked packages, searched alongside the channel-less rows rather than
// in place of them).
func TestRapidFortUbuntu_Matching(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortUbuntu, "20.04", "")

	// streamFinding is one expected finding for the test's CVE, identified by the namespace it
	// was found in — a package routed to a stream channel surfaces one finding per searched
	// namespace that carries the CVE.
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
			// native (ubuntu-versioned) package resolves against the channel-less namespace
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
			// the same package under a plain ubuntu distro must not reach rapidfort data
			name:       "plain ubuntu distro never sees rapidfort rows",
			pkgName:    "curl",
			pkgVersion: "7.68.0-1ubuntu2.5",
			d:          distro.New(distro.Ubuntu, "20.04", ""),
			expectNone: true,
		},
		{
			// an rf-versioned package adds the +rf channel to the query, and the channel-less rows
			// are still searched. Both streams describe this build as vulnerable, but they name
			// different fixes: the rf stream is the one that built this package, so its fix is the
			// one that applies and the native row it outranks is not reported alongside it
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
			// a native-versioned package matches no routing rule, so only the channel-less rows are
			// searched and the rf-stream fix for the same CVE stays out of the result
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
			// an rf-named package with a stock ubuntu version stays on the native stream (rf-named
			// advisory files carry native events for stock builds; ubuntu derives streams from
			// versions only) and matches by exact name
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
			// a rapidfort distro version with no rows in the DB yields zero matches, no error
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

// TestRapidFortUbuntu_StreamFixResolvesNativeDisclosure pins the behavior that keeps a RapidFort
// rebuild from being reported against a disclosure its own stream has already fixed.
//
// CVE-2026-11111 is recorded twice for openssl: the channel-less rapidfort-ubuntu:20.04 rows carry
// an open-ended `>= 1.1.1-1ubuntu2` affected range with no fix, and the rapidfort-ubuntu:20.04+rf
// channel carries the rebuild's fix at 1.1.1-3rfubu.1. Both namespaces are searched for an
// rf-versioned package, so without the resolution step the native row alone would report every
// rf build as vulnerable no matter how far past the rebuild fix it is.
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

				// no matches; the resolved CVE is carried out as a DistroPackageFixed ignore for
				// packages this one owns files for, the same as any other already-fixed CVE
				findings := db.Match(t, matcher, p)
				findings.OnlyHasVulnerabilities()
				findings.Ignores().
					SelectRelatedPackageIgnores("DistroPackageFixed", "CVE-2026-11111").
					ForPackage(pkgID)
			})

			// an rf build below the native row's lower bound: the native row has nothing to say about
			// it, and silence is not a denial -- the rf row does cover it, so the finding stands.
			t.Run("a native row that does not cover this build does not resolve anything", func(t *testing.T) {
				p := dbtest.NewPackage("openssl", "1.1.1-0rfubu.1", syftPkg.DebPkg).WithDistro(rfDistro).Build()

				db.Match(t, matcher, p).
					SkipCompleteness().
					SelectMatches("CVE-2026-11111").
					HasCount(1).
					WithNamespace("rapidfort:distro:rapidfort-ubuntu:20.4+rf").
					HasFix(vulnerability.FixStateFixed, "1.1.1-3rfubu.1")
			})

			// both rows match a build below the rebuild fix, but they disagree: the native row has no
			// fix and the rf row names one. Reporting both would emit two findings for one package
			// and one CVE that are identical in the output apart from that contradiction, so only
			// the row that names the fix is kept.
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
