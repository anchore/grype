package rpm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/search"
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

// A release the RapidFort feed does not publish is searched as its base distro, which the identifier
// leads ID_LIKE with. CVE-2023-38546 is fixed for curl in rhel:8 and rhel:9 and absent from the RapidFort
// feed, which publishes no rapidfort-redhat:8. The fixture is extracted from the rapidfort and rhel
// vunnel runs.
func TestRapidFortRedHat_UnpublishedReleaseFallsBackToBaseDistro(t *testing.T) {
	dbtest.DBs(t, "rapidfort-redhat-with-rhel").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{})

		t.Run("control: plain redhat 9 finds the base distro CVE", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RedHat, "9", "")).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2023-38546")
		})

		t.Run("a published release finds the RapidFort feed CVE", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "9", "", "redhat")).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2025-14017")
		})

		t.Run("an unpublished release finds the base distro CVE", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.61.1-22.el8", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "8", "", "redhat")).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2023-38546")
		})
	})
}

// An el9 build on a RHEL 10 image is searched in the el9 channel at priority 20, beside its own
// channel-less search at priority 0. A NAK only denies a candidate found at its own priority or lower,
// so a channel-less NAK does not remove the el9 stream's affected record. The fixture is hand-written,
// since the feed carries no NAK records.
func TestRapidFortRedHat_LowerRankedNAKDoesNotDenyHigherRankedFinding(t *testing.T) {
	rhel10 := distro.New(distro.RapidFortRedHat, "10", "")

	dbtest.DBs(t, "rapidfort-redhat-nak").Run(func(t *testing.T, db *dbtest.DB) {
		matcher := NewRpmMatcher(MatcherConfig{})

		t.Run("control: the el9 stream holds an affected record for the package", func(t *testing.T) {
			el9Stream := *rhel10
			el9Stream.Channels = []string{"el9"}

			vulns, err := db.FindVulnerabilities(search.ByPackageName("curl"), search.ByDistro(el9Stream))
			require.NoError(t, err)
			require.Len(t, vulns, 1)
			require.Equal(t, "CVE-2026-90002", vulns[0].ID)
		})

		t.Run("the el9 stream's affected record survives a channel-less NAK", func(t *testing.T) {
			p := dbtest.NewPackage("curl", "0:7.76.1-14.el9", syftPkg.RpmPkg).WithDistro(rhel10).Build()

			db.Match(t, matcher, p).SkipCompleteness().ContainsVulnerabilities("CVE-2026-90002")
		})
	})
}

// every DB published before 6.1.11 has no search_rules table, but hydrating it (what the curator does on
// import) auto-migrates the current models and so creates the table, empty. A client that took an
// existing table as authoritative would apply no rules to these DBs, losing the built-in rules, and a
// RapidFort rebuild would be searched in the image release's own rows.
func TestRapidFortRedHat_HydratedPre611DBKeepsBuiltInRules(t *testing.T) {
	dbtest.DBs(t, "rapidfort-redhat-with-rhel").Run(func(t *testing.T, fixture *dbtest.DB) {
		dir := t.TempDir()
		content, err := os.ReadFile(filepath.Join(fixture.Path, v6.VulnerabilityDBFileName))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, v6.VulnerabilityDBFileName), content, 0o600)) //nolint:gosec // dir is t.TempDir()

		// make the copy look like a 6.1.10 DB: no search_rules table, addition 10
		gdb, err := v6.NewLowLevelDB(filepath.Join(dir, v6.VulnerabilityDBFileName), false, true, false)
		require.NoError(t, err)
		require.NoError(t, gdb.Migrator().DropTable(&v6.SearchRule{}))
		require.NoError(t, gdb.Model(&v6.DBMetadata{}).Where("true").Update("addition", 10).Error)
		sqlDB, err := gdb.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())

		require.NoError(t, v6.Hydrater()(dir))

		// the trap: hydration left an empty table behind
		gdb, err = v6.NewLowLevelDB(filepath.Join(dir, v6.VulnerabilityDBFileName), false, false, false)
		require.NoError(t, err)
		require.True(t, gdb.Migrator().HasTable(&v6.SearchRule{}), "hydration should create the search_rules table")
		var count int64
		require.NoError(t, gdb.Model(&v6.SearchRule{}).Count(&count).Error)
		require.Zero(t, count, "hydration should not seed search rules")
		sqlDB, err = gdb.DB()
		require.NoError(t, err)
		require.NoError(t, sqlDB.Close())

		rdr, err := v6.NewReader(v6.Config{DBDirPath: dir})
		require.NoError(t, err)
		t.Cleanup(func() { _ = rdr.Close() })
		provider := v6.NewVulnerabilityProvider(rdr)

		// the built-in rules apply: a RapidFort rebuild is searched in the rf channel alone
		p := dbtest.NewPackage("curl", "0:7.76.1-14.el9.rf.1", syftPkg.RpmPkg).WithDistro(distro.New(distro.RapidFortRedHat, "9", "")).Build()
		searches, rewritten := provider.(v6.SearchRuleProvider).SearchRewrites(p, []vulnerability.Criteria{
			search.ByPackageName(p.Name), search.ByDistro(*p.Distro), search.WithPackage(p),
		})
		require.True(t, rewritten)
		require.Len(t, searches, 1)
		var channels []string
		for _, c := range searches[0] {
			if dc, ok := c.(*search.DistroCriteria); ok {
				for _, d := range dc.Distros {
					channels = append(channels, d.Channels...)
				}
			}
		}
		require.Equal(t, []string{"rf"}, channels)
	})
}
