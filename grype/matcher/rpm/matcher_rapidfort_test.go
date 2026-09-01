package rpm

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// The rapidfort-redhat fixture carries curated advisories under the rapidfort-redhat OS name:
// native el9-stream fixes live in the channel-less rapidfort-redhat:9 namespace, Fedora-stream
// fixes live in the rapidfort-redhat:9+fc43 channel, and RapidFort-rebuild fixes live in the
// rapidfort-redhat:9+rf channel. The stock rpm matcher resolves these through the per-package OS
// routing rules (a .fcNN dist tag adds the matching fc channel; .rf markers add +rf), each of
// which searches its channel *in addition to* the channel-less rows — so a package built in a
// foreign stream surfaces both that stream's fix and whatever the native rows carry for it.
func TestRapidFortRedHat_Matching(t *testing.T) {
	rfDistro := distro.New(distro.RapidFortRedHat, "9", "")

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
			// a native el9 rpm needs no routing rule: the channel-less query IS the native stream
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
			// a .fc43 rpm routes to the +fc43 channel and keeps the channel-less rows: its version is
			// inside both streams' constraints, but the fedora stream is the one that built this
			// rpm, so its fix is the one that applies and the native row it outranks is not
			// reported alongside it
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
			// a .rf-versioned rpm routes to the +rf channel via the version-marker rule; the
			// channel-less rows are searched too but carry nothing for this package
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
			// an rf-named rpm with no derivable version marker routes to +rf via the name
			// fallback rule (which runs after all version-marker rules)
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
			// source-rpm indirection composes with routing: the synthesized upstream package
			// carries the same el9 version and resolves against the native rows
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
			// the same package under a plain redhat distro must not reach rapidfort data
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
