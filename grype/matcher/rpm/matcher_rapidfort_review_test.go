package rpm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// review tests for #3751: each "control" subtest passes today and proves the fixture and the path work;
// each other subtest asserts the behavior the review asks for and fails today. The R1 fixture
// (testdata/review-rapidfort-redhat) is extracted from the rapidfort and rhel vunnel runs; the R12
// fixture (testdata/review-rapidfort-nak) is hand-written since the feed carries no NAK records.

// R1: once a package's distro is remapped to rapidfort-*, its OS searches never reach the base distro's
// rows, so a CVE the base distro has and the RapidFort feed lacks scans clean, as does a whole release
// the feed does not publish. CVE-2023-38546 is fixed for curl in rhel:8 and rhel:9 and absent from the
// RapidFort feed; the feed publishes no rapidfort-redhat:8 at all. Nothing here can see the debug log the miss produces; the loud-failure half
// of the agreed fix needs its own assertion on the log or a returned warning.
func TestReview_R1_RapidFortRemapHasNoBaseDistroFallback(t *testing.T) {
	dbtest.DBs(t, "review-rapidfort-redhat").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{})

		t.Run("control: plain redhat 9 finds the base distro CVE", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RedHat, "9", "")).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2023-38546")
		})

		t.Run("control: rapidfort-redhat 9 finds the RapidFort feed CVE", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "9", "")).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2025-14017")
		})

		t.Run("a CVE missing from the RapidFort feed falls back to the base distro", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "9", "")).Build()

			// today: only the RapidFort feed's CVEs, the rhel:9 record is never searched
			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2023-38546")
		})

		t.Run("a release the RapidFort feed does not publish falls back to the base distro", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.61.1-22.el8", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "8", "")).Build()

			// today: no rapidfort-redhat:8 OS rows, ErrOSNotPresent is swallowed and the package scans clean
			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2023-38546")
		})
	})
}

// R12: a NAK denies a candidate regardless of rank. The built-in el rule searches an el9 build on a
// RHEL 10 image in the el9 channel at priority 20, beside the package's own channel-less search at
// priority 0, and its comment says the el9 records "then outrank the channel-less ones". A channel-less
// NAK still removes the higher-ranked affected record.
func TestReview_R12_LowerRankedNAKDeniesHigherRankedAffectedRecord(t *testing.T) {
	rhel10 := distro.New(distro.RapidFortRedHat, "10", "")

	dbtest.DBs(t, "review-rapidfort-nak").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{})

		t.Run("control: the el9 stream holds an affected record for the package", func(t *testing.T) {
			el9Stream := *rhel10
			el9Stream.Channels = []string{"el9"}

			vulns, err := db.FindVulnerabilities(search.ByPackageName("curl"), search.ByDistro(el9Stream))
			require.NoError(t, err)
			require.Len(t, vulns, 1)
			require.Equal(t, "CVE-2026-90002", vulns[0].ID)
		})

		t.Run("the higher-ranked el9 stream's affected record survives a channel-less NAK", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(rhel10).Build()

			// today: the rank 0 NAK removes the rank 20 record, so CVE-2026-90002 is not reported. The losing
			// NAK also comes back as a "Distro Not Vulnerable" ignore for the same CVE (the completeness check
			// reports it), which a fix has to drop too or the ignore suppresses the match it reports
			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2026-90002")
		})
	})
}
