package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The rapidfort-redhat fixture holds native el9 fixes in the channel-less rapidfort-redhat:9
// namespace, Fedora-stream fixes in rapidfort-redhat:9+fc43, and RapidFort-rebuild fixes in
// rapidfort-redhat:9+rf. Search rules add the fc/rf channel for marked packages, searched in
// addition to the channel-less rows.
func TestRapidFortRedHat_Matching(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortRedHat, "9", "")

	// streamFinding is one expected finding for the test's CVE, identified by namespace
	type streamFinding struct {
		namespace string
		fixes     []string
	}

	tests := []struct {
		name        string
		pkgName     string
		pkgVersion  string
		upstream    string
		upstreamVer string
		d           *distro.Distro
		expectCVE   string
		expectType  match.Type
		expectState vulnerability.FixState
		expect      []streamFinding
		expectNone  bool
	}{
		{
			name:        "el9 rpm surfaces the native fix",
			pkgName:     "curl",
			pkgVersion:  "0:7.76.1-14.el9",
			d:           rfDistro,
			expectCVE:   "CVE-2023-38546",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-redhat:9", fixes: []string{"0:7.76.1-19.el9_2"}},
			},
		},
		{
			// both streams cover this version; the fedora stream outranks the native row
			name:        "fc43 rpm surfaces the fedora-stream fix, not the native one",
			pkgName:     "curl",
			pkgVersion:  "7.70.0-1.fc43",
			d:           rfDistro,
			expectCVE:   "CVE-2023-38546",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-redhat:9+fc43", fixes: []string{"7.78.0-4.fc43"}},
			},
		},
		{
			// the channel-less rows carry nothing for this package
			name:        "rf-versioned rpm surfaces the rf-stream fix",
			pkgName:     "python3",
			pkgVersion:  "0:3.11.14-1.rf",
			d:           rfDistro,
			expectCVE:   "CVE-2024-6923",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-redhat:9+rf", fixes: []string{"0:3.11.15-2.rf"}},
			},
		},
		{
			name:        "rf-named rpm with an unmarked version falls back to the rf channel",
			pkgName:     "rf-polkit",
			pkgVersion:  "0:0.117-10",
			d:           rfDistro,
			expectCVE:   "CVE-2021-4034",
			expectType:  match.ExactDirectMatch,
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-redhat:9+rf", fixes: []string{"0:0.117-11.rf"}},
			},
		},
		{
			name:        "source-rpm indirection reaches the native fix",
			pkgName:     "curl-minimal",
			pkgVersion:  "0:7.76.1-14.el9",
			upstream:    "curl",
			upstreamVer: "7.76.1-14.el9",
			d:           rfDistro,
			expectCVE:   "CVE-2023-38546",
			expectType:  match.ExactIndirectMatch,
			expectState: vulnerability.FixStateFixed,
			expect: []streamFinding{
				{namespace: "rapidfort:distro:rapidfort-redhat:9", fixes: []string{"0:7.76.1-19.el9_2"}},
			},
		},
		{
			name:       "plain redhat distro never sees rapidfort rows",
			pkgName:    "curl",
			pkgVersion: "0:7.76.1-14.el9",
			d:          distro.New(distro.RedHat, "9", ""),
			expectNone: true,
		},
	}

	dbtest.DBs(t, "rapidfort-redhat").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{})

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				b := dbtest.NewPackage(tt.pkgName, tt.pkgVersion, syftPkg.RpmPkg).WithDistro(tt.d)
				if tt.upstream != "" {
					b = b.WithUpstream(tt.upstream, tt.upstreamVer)
				}
				p := b.Build()

				findings := db.Match(t, matcher, p)

				if tt.expectNone {
					findings.IsEmpty()
					return
				}

				matches := findings.SkipCompleteness().SelectMatches(tt.expectCVE).HasCount(len(tt.expect))
				for _, e := range tt.expect {
					sf := matches.WithNamespace(e.namespace)
					sf.HasMatchType(tt.expectType)
					sf.HasFix(tt.expectState, e.fixes...)
				}
			})
		}
	})
}

// a RapidFort image falls back to the base distro's records where the RapidFort feed has none, ranked
// below the feed's own, so a base distro NAK cannot hide a finding the feed reports. rhel:9 NAKs
// CVE-2026-61711 for podman, which rapidfort-redhat:9 reports affected at every version.
func TestRapidFortRedHat_BaseDistroNAKDoesNotDenyFeedFinding(t *testing.T) {
	const cve = "CVE-2026-61711"

	dbtest.DBs(t, "review-rapidfort-redhat").
		SelectOnly("rapidfort-redhat:9/cve-2026-61711", "rhel:9/cve-2026-61711").
		Run(func(t *testing.T, db *dbtest.DB) {
			matcher := NewRpmMatcher(MatcherConfig{})

			t.Run("control: plain redhat 9 takes the NAK", func(t *testing.T) {
				p := dbtest.NewPackage("podman", "5:5.6.0-5.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RedHat, "9", "")).Build()

				db.Match(t, matcher, p).Ignores().SelectRelatedPackageIgnore(IgnoreReasonDistroNotVulnerable, cve)
			})

			// ignore completeness fails the test if the outranked NAK still comes back as an ignore
			t.Run("rapidfort-redhat 9 reports the feed's finding and not the outranked NAK", func(t *testing.T) {
				p := dbtest.NewPackage("podman", "5:5.6.0-5.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "9", "")).Build()

				db.Match(t, matcher, p).SelectMatch(cve).
					InNamespace("rapidfort:distro:rapidfort-redhat:9").
					SelectDetailByType(match.ExactDirectMatch).
					AsDistroSearch()
			})
		})
}
