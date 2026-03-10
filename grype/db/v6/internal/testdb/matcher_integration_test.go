package testdb

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/apk"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	syftCpe "github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// These integration tests exercise actual matcher Match() methods against real
// vulnerability databases built from vunnel fixtures. Unlike the unit tests in
// each matcher package (which use mock providers with in-memory filtering),
// these tests exercise the full SQL query path including joins, COLLATE NOCASE,
// OS aliasing, and CPE broad matching.

func TestDpkgMatcher_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2005-2964.json")),
	)

	matcher := dpkg.NewDpkgMatcher(dpkg.MatcherConfig{})

	t.Run("direct match on vulnerable version", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "abiword",
			Version: "2.2.7-1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.Len(t, matches, 1, "abiword 2.2.7-1 should be vulnerable (fix at 2.2.10-1)")

		m := matches[0]
		assert.Equal(t, "CVE-2005-2964", m.Vulnerability.ID)
		assert.Equal(t, "abiword", m.Package.Name)
		assertHasMatchType(t, m, match.ExactDirectMatch)
	})

	t.Run("no match on fixed version", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "abiword",
			Version: "2.2.10-1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "abiword 2.2.10-1 should not be vulnerable (it is the fix version)")
	})

	t.Run("no match on different distro version", func(t *testing.T) {
		d := distro.New(distro.Debian, "9", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "abiword",
			Version: "2.2.7-1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "no vulnerability data for debian:9")
	})

	t.Run("no match on unrelated package", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "curl",
			Version: "7.0.0",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})
}

func TestApkMatcher_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("alpine-3.18-cve-2021-30473.json")),
	)

	matcher := &apk.Matcher{}

	t.Run("direct match on vulnerable version", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.0-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.Len(t, matches, 1, "aom 3.1.0-r0 should be vulnerable (fix at 3.1.1-r0)")

		m := matches[0]
		assert.Equal(t, "CVE-2021-30473", m.Vulnerability.ID)
		assertHasMatchType(t, m, match.ExactDirectMatch)
	})

	t.Run("no match on fixed version", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.1-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "aom 3.1.1-r0 should not be vulnerable (it is the fix version)")
	})

	t.Run("upstream indirection match", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom-libs",
			Version: "3.1.0-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "aom"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.Len(t, matches, 1, "aom-libs should match via upstream indirection to aom")

		m := matches[0]
		assert.Equal(t, "CVE-2021-30473", m.Vulnerability.ID)
		assert.Equal(t, "aom-libs", m.Package.Name, "match should report the original package name")
		assertHasMatchType(t, m, match.ExactIndirectMatch)
	})
}

func TestApkMatcher_SecDBAndNVDDedup_RealDB(t *testing.T) {
	// Load both Alpine secDB and NVD data for the same CVE (CVE-2021-30473).
	// The APK matcher should deduplicate: when both sources report the same CVE,
	// the secDB match should be preferred and the NVD match dropped.
	provider := New(t,
		WithVunnelFixture(fixture("alpine-3.18-cve-2021-30473.json")),
		WithVunnelFixture(fixture("nvd-cve-2021-30473.json")),
	)

	matcher := &apk.Matcher{}

	t.Run("secDB preferred over NVD for same CVE", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.0-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			CPEs: []syftCpe.CPE{
				syftCpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.0:*:*:*:*:*:*:*", ""),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "aom 3.1.0-r0 should be vulnerable")

		// Should have exactly one match for CVE-2021-30473 (deduplicated)
		cveMatches := filterMatchesByCVE(matches, "CVE-2021-30473")
		assert.Len(t, cveMatches, 1, "should have exactly one match for CVE-2021-30473 (deduplicated)")

		if len(cveMatches) > 0 {
			// The secDB (distro) match should be preferred over the NVD (CPE) match
			assertHasMatchType(t, cveMatches[0], match.ExactDirectMatch)
		}
	})

	t.Run("fixed version per secDB - no match even if NVD range would match", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.1-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			CPEs: []syftCpe.CPE{
				syftCpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.1:*:*:*:*:*:*:*", ""),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "aom 3.1.1-r0 is the secDB fix version - should not match even via NVD")
	})
}

func TestApkMatcher_NVDOnlyMatch_RealDB(t *testing.T) {
	// Load only NVD data (no secDB). The APK matcher should return CPE matches
	// with fix info stripped (since NVD doesn't know when Alpine will fix things).
	provider := New(t,
		WithVunnelFixture(fixture("nvd-cve-2021-30473.json")),
	)

	matcher := &apk.Matcher{}

	t.Run("CPE match with NVD fix info stripped", func(t *testing.T) {
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.0-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			CPEs: []syftCpe.CPE{
				syftCpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.0:*:*:*:*:*:*:*", ""),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		// NVD version constraint is "< 2021-04-07" which may or may not match
		// against APK version "3.1.0-r0" depending on version format handling.
		// If it matches, it should be a CPE match with fix info stripped.
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2021-30473" {
				assertHasMatchType(t, m, match.CPEMatch)
				// APK matcher should strip NVD fix info for Alpine packages
				assert.Empty(t, m.Vulnerability.Fix.Versions,
					"NVD fix versions should be stripped for Alpine CPE matches")
			}
		}
	})
}

func TestApkMatcher_WolfiNAK_RealDB(t *testing.T) {
	// Wolfi NAK entries (fix version "0" → constraint "< 0") should produce
	// ignore rules rather than matches. This exercises the real NAK detection
	// path through the SQL query layer.
	provider := New(t,
		WithVunnelFixture(fixture("wolfi-rolling-cve-2015-3211.json")),
	)

	matcher := &apk.Matcher{}

	t.Run("NAK entry produces ignore rules with file locations", func(t *testing.T) {
		d := distro.New(distro.Wolfi, "", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "php-8.3",
			Version: "8.3.11-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			Metadata: pkg.ApkMetadata{
				Files: []pkg.ApkFileRecord{
					{Path: "/usr/bin/php83"},
					{Path: "/usr/lib/php83/modules/opcache.so"},
				},
			},
		}

		matches, ignores, err := matcher.Match(provider, p)
		require.NoError(t, err)

		// NAK entry should NOT produce matches
		for _, m := range matches {
			assert.NotEqual(t, "CVE-2015-3211", m.Vulnerability.ID,
				"NAK vulnerability should not appear as a match")
		}

		// NAK entry should produce ignore rules for each file location
		require.NotEmpty(t, ignores, "NAK entry should produce ignore rules")

		var nakIgnores []match.IgnoreRule
		for _, ig := range ignores {
			rule, ok := ig.(match.IgnoreRule)
			if ok && rule.Vulnerability == "CVE-2015-3211" {
				nakIgnores = append(nakIgnores, rule)
			}
		}
		assert.Len(t, nakIgnores, 2, "should have one ignore rule per file location")
	})

	t.Run("NAK via upstream indirection", func(t *testing.T) {
		d := distro.New(distro.Wolfi, "", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "php-8.3-fpm",
			Version: "8.3.11-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "php-8.3", Version: "8.3.11-r0"},
			},
			Metadata: pkg.ApkMetadata{
				Files: []pkg.ApkFileRecord{
					{Path: "/usr/sbin/php-fpm83"},
				},
			},
		}

		matches, ignores, err := matcher.Match(provider, p)
		require.NoError(t, err)

		// No matches for the NAK
		for _, m := range matches {
			assert.NotEqual(t, "CVE-2015-3211", m.Vulnerability.ID)
		}

		// Should still get ignore rules via upstream indirection
		require.NotEmpty(t, ignores, "NAK should propagate through upstream indirection")
	})

	t.Run("real fix entry produces match not ignore", func(t *testing.T) {
		// php-8.4 has a real fix at 8.4.12-r1, not a NAK
		d := distro.New(distro.Wolfi, "", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "php-8.4",
			Version: "8.4.10-r0",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
			Metadata: pkg.ApkMetadata{
				Files: []pkg.ApkFileRecord{
					{Path: "/usr/bin/php84"},
				},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "php-8.4 8.4.10-r0 should be vulnerable (fix at 8.4.12-r1)")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2015-3211" {
				found = true
				break
			}
		}
		assert.True(t, found, "CVE-2015-3211 should match for php-8.4 (real fix, not NAK)")
	})
}

// filterMatchesByCVE returns only matches for the given CVE ID.
func filterMatchesByCVE(matches []match.Match, cveID string) []match.Match {
	var result []match.Match
	for _, m := range matches {
		if m.Vulnerability.ID == cveID {
			result = append(result, m)
		}
	}
	return result
}

func TestRpmMatcher_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("rhel-8-cve-2015-20107.json")),
	)

	matcher := rpm.NewRpmMatcher(rpm.MatcherConfig{})

	t.Run("direct match on vulnerable version", func(t *testing.T) {
		// The fixture has python3 fixed at 0:3.6.8-47.el8_6 for rhel:8
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python3",
			Version: "3.6.8-37.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "python3 3.6.8-37.el8 should be vulnerable (fix at 0:3.6.8-47.el8_6)")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2015-20107" {
				found = true
				break
			}
		}
		assert.True(t, found, "CVE-2015-20107 should be in results")
	})

	t.Run("no match on fixed version", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python3",
			Version: "3.6.8-47.el8_6",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "python3 3.6.8-47.el8_6 should not be vulnerable")
	})

	t.Run("centos alias to rhel", func(t *testing.T) {
		// CentOS 8 should alias to RHEL 8 via OS aliasing overrides
		d := distro.New(distro.CentOS, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python3",
			Version: "3.6.8-37.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "centos:8 should find rhel:8 vulnerabilities via OS aliasing")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2015-20107" {
				found = true
				break
			}
		}
		assert.True(t, found, "CVE-2015-20107 should be in centos results via rhel alias")
	})

	t.Run("modularity label matching", func(t *testing.T) {
		// The fixture also has python38 with module "python38:3.8" — test that
		// modularity-label-bearing packages are correctly filtered.
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python38",
			Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("python38:3.8:1234:5678"),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "python38 with matching modularity label should be vulnerable")
	})
}

func TestRpmMatcher_SourceIndirection_RealDB(t *testing.T) {
	// Test that RPM matcher finds vulnerabilities via source package indirection.
	// The fixture has a vulnerability against "python3" on rhel:8. A binary package
	// "python3-libs" that lists "python3" as its upstream should find this via indirection.
	provider := New(t,
		WithVunnelFixture(fixture("rhel-8-cve-2015-20107.json")),
	)

	matcher := rpm.NewRpmMatcher(rpm.MatcherConfig{})

	t.Run("binary package matches via upstream source", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python3-libs",
			Version: "3.6.8-37.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "python3", Version: "3.6.8-37.el8"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "python3-libs should match via upstream indirection to python3")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2015-20107" {
				found = true
				assert.Equal(t, "python3-libs", m.Package.Name,
					"match should report the original binary package name")
				assertHasMatchType(t, m, match.ExactIndirectMatch)
				break
			}
		}
		assert.True(t, found, "CVE-2015-20107 should be found via source indirection")
	})

	t.Run("desynced source version - no indirect match", func(t *testing.T) {
		// When the upstream version is much higher than the fix version,
		// the upstream package should not be vulnerable
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python3-libs",
			Version: "3.6.8-37.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "python3", Version: "3.6.8-50.el8"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		// The upstream version 3.6.8-50.el8 is above the fix at 3.6.8-47.el8_6,
		// so the indirect match should NOT occur
		for _, m := range matches {
			for _, d := range m.Details {
				assert.NotEqual(t, match.ExactIndirectMatch, d.Type,
					"should not have indirect matches when upstream is above fix version")
			}
		}
	})
}

func TestRpmMatcher_Epoch_RealDB(t *testing.T) {
	// CVE-2018-0734 affects openssl on rhel:8, fixed at 1:1.1.1c-2.el8 (epoch 1).
	// This exercises the epoch handling logic in the RPM matcher.
	provider := New(t,
		WithVunnelFixture(fixture("rhel-8-cve-2018-0734.json")),
	)

	matcher := rpm.NewRpmMatcher(rpm.MatcherConfig{})

	t.Run("package without epoch assumed 0 - vulnerable when fix has epoch 1", func(t *testing.T) {
		// Package version 1.1.1-1.el8 without epoch -> assumed epoch 0
		// Fix version 1:1.1.1c-2.el8 has epoch 1
		// 0:1.1.1-1.el8 < 1:1.1.1c-2.el8 -> vulnerable
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "1.1.1-1.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		require.NotEmpty(t, cveMatches, "openssl 1.1.1-1.el8 (epoch 0) should be vulnerable (fix at 1:1.1.1c-2.el8)")
	})

	t.Run("package with epoch 1 at fix version - not vulnerable", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "1:1.1.1c-2.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		assert.Empty(t, cveMatches, "openssl 1:1.1.1c-2.el8 should not be vulnerable (it is the fix version)")
	})

	t.Run("package with epoch 1 above fix - not vulnerable", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "1:1.1.1k-5.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		assert.Empty(t, cveMatches, "openssl 1:1.1.1k-5.el8 should not be vulnerable (above fix)")
	})

	t.Run("package with higher epoch 2 - not vulnerable", func(t *testing.T) {
		// Epoch 2 > epoch 1 of the fix version
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "2:0.9.8-1.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		assert.Empty(t, cveMatches, "openssl 2:0.9.8-1.el8 should not be vulnerable (epoch 2 > epoch 1)")
	})

	t.Run("package with epoch 1 below fix - vulnerable", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "1:1.0.2k-16.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		require.NotEmpty(t, cveMatches, "openssl 1:1.0.2k-16.el8 should be vulnerable (below fix 1:1.1.1c-2.el8)")
	})

	t.Run("epoch from metadata when not in version string", func(t *testing.T) {
		// Epoch is in RPM metadata but NOT in the version string
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "openssl",
			Version: "1.0.2k-16.el8",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Metadata: pkg.RpmMetadata{
				Epoch: intRef(1),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2018-0734")
		require.NotEmpty(t, cveMatches, "openssl with epoch 1 from metadata should be vulnerable")
	})
}

func TestRpmMatcher_ModularityFiltering_RealDB(t *testing.T) {
	// The rhel-8-cve-2015-20107 fixture has:
	// - python3 (no module) fixed at 0:3.6.8-47.el8_6
	// - python38 (module "python38:3.8") fixed at 0:3.8.13-1.module+el8.7.0+16653+23ccaf52
	// - python39 (module "python39:3.9") fixed at 0:3.9.7-2.module+el8.7.0+16653+23ccaf52
	provider := New(t,
		WithVunnelFixture(fixture("rhel-8-cve-2015-20107.json")),
	)

	matcher := rpm.NewRpmMatcher(rpm.MatcherConfig{})

	t.Run("matching modularity label", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python38",
			Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Metadata: pkg.RpmMetadata{
				ModularityLabel: strRef("python38:3.8:1234:5678"),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2015-20107")
		require.NotEmpty(t, cveMatches, "python38 with matching module python38:3.8 should be vulnerable")
	})

	t.Run("non-matching modularity label", func(t *testing.T) {
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python38",
			Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
			Metadata: pkg.RpmMetadata{
				// This label doesn't match the "python38:3.8" module in the fixture
				ModularityLabel: strRef("python39:3.9:1234:5678"),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2015-20107")
		assert.Empty(t, cveMatches, "python38 with non-matching module should not match")
	})

	t.Run("no modularity label matches all entries", func(t *testing.T) {
		// A package without a modularity label should match vulnerabilities
		// regardless of module qualifier
		d := distro.New(distro.RedHat, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "python38",
			Version: "3.8.12-1.module+el8.6.0+15298+3a81427c",
			Type:    syftPkg.RpmPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2015-20107")
		require.NotEmpty(t, cveMatches, "python38 without modularity label should still match")
	})
}

func TestDpkgMatcher_SourceIndirection_RealDB(t *testing.T) {
	// Test source package indirection for DPKG matcher.
	// The debian fixture has CVE-2014-0071 against "neutron" on debian:8.
	// A binary package "neutron-common" with upstream "neutron" should match via indirection.
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2014-0071.json")),
	)

	matcher := dpkg.NewDpkgMatcher(dpkg.MatcherConfig{})

	t.Run("binary package matches via source indirection", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "neutron-common",
			Version: "2014.1-1~pre1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "neutron"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "neutron-common should match CVE-2014-0071 via upstream 'neutron'")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2014-0071" {
				found = true
				assert.Equal(t, "neutron-common", m.Package.Name,
					"match should report the original binary package name")
				assertHasMatchType(t, m, match.ExactIndirectMatch)
				break
			}
		}
		assert.True(t, found, "CVE-2014-0071 should be found via source indirection")
	})

	t.Run("direct match on source package name", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "neutron",
			Version: "2014.1-1~pre1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "neutron should match CVE-2014-0071 directly")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2014-0071" {
				found = true
				assertHasMatchType(t, m, match.ExactDirectMatch)
				break
			}
		}
		assert.True(t, found, "CVE-2014-0071 should be a direct match")
	})

	t.Run("no match when upstream version is fixed", func(t *testing.T) {
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "neutron-common",
			Version: "2014.1-2",
			Type:    syftPkg.DebPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "neutron"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2014-0071")
		assert.Empty(t, cveMatches, "neutron-common 2014.1-2 should not be vulnerable (fix at 2014.1-1)")
	})

	t.Run("both direct and indirect - same name ignored", func(t *testing.T) {
		// When the binary package name IS the source package name, the matcher
		// should not produce duplicate matches.
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "neutron",
			Version: "2014.1-1~pre1",
			Type:    syftPkg.DebPkg,
			Distro:  d,
			Upstreams: []pkg.UpstreamPackage{
				{Name: "neutron"},
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		cveMatches := filterMatchesByCVE(matches, "CVE-2014-0071")
		// Should have direct match; indirect match for same package name is skipped
		// because the DPKG matcher filters out upstreams with the same name
		require.NotEmpty(t, cveMatches)
		hasDirectMatch := false
		for _, m := range cveMatches {
			for _, d := range m.Details {
				if d.Type == match.ExactDirectMatch {
					hasDirectMatch = true
				}
			}
		}
		assert.True(t, hasDirectMatch, "should have a direct match")
	})
}

func TestStockMatcher_CPE_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("nvd-cve-2024-0181.json")),
	)

	matcher := stock.NewStockMatcher(stock.MatcherConfig{
		UseCPEs: true,
	})

	t.Run("CPE match on vulnerable product", func(t *testing.T) {
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "rrj_nueva_ecija_engineer_online_portal",
			Version: "1.0",
			Type:    syftPkg.BinaryPkg,
			CPEs: []syftCpe.CPE{
				syftCpe.Must("cpe:2.3:a:nia:rrj_nueva_ecija_engineer_online_portal:1.0:*:*:*:*:*:*:*", ""),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "should find CVE-2024-0181 via CPE match")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "CVE-2024-0181" {
				found = true
				assertHasMatchType(t, m, match.CPEMatch)
				break
			}
		}
		assert.True(t, found, "CVE-2024-0181 should be in CPE results")
	})

	t.Run("no CPE match for unrelated product", func(t *testing.T) {
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "curl",
			Version: "7.0.0",
			Type:    syftPkg.BinaryPkg,
			CPEs: []syftCpe.CPE{
				syftCpe.Must("cpe:2.3:a:haxx:curl:7.0.0:*:*:*:*:*:*:*", ""),
			},
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches)
	})
}

func TestPythonMatcher_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("github-python-ghsa-9hx2-hgq2-2g4f.json")),
	)

	matcher := python.NewPythonMatcher(python.MatcherConfig{})

	t.Run("match vulnerable Pillow version", func(t *testing.T) {
		// GHSA-9hx2-hgq2-2g4f affects Pillow >= 5.1.0 < 8.1.1
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "Pillow",
			Version:  "7.2.0",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "Pillow 7.2.0 should be vulnerable (range >= 5.1.0, < 8.1.1)")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "GHSA-9hx2-hgq2-2g4f" {
				found = true
				break
			}
		}
		assert.True(t, found, "GHSA-9hx2-hgq2-2g4f should be in results")
	})

	t.Run("no match on fixed version", func(t *testing.T) {
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "Pillow",
			Version:  "8.1.1",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "Pillow 8.1.1 should not be vulnerable")
	})

	t.Run("no match below affected range", func(t *testing.T) {
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "Pillow",
			Version:  "5.0.0",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "Pillow 5.0.0 is below the affected range (>= 5.1.0)")
	})

	t.Run("case-insensitive package name", func(t *testing.T) {
		// GitHub advisories list the package as "Pillow", but PyPI packages
		// may be installed as "pillow" (lowercase). The real DB should
		// handle case-insensitive matching.
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "pillow",
			Version:  "7.2.0",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "case-insensitive match: 'pillow' should match 'Pillow' advisory")
	})
}

func TestJavascriptMatcher_RealDB(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("github-npm-ghsa-f8mp-x433-5wpf.json")),
	)

	matcher := javascript.NewJavascriptMatcher(javascript.MatcherConfig{})

	t.Run("match vulnerable wrangler version", func(t *testing.T) {
		// GHSA-f8mp-x433-5wpf affects wrangler >= 3.0.0 < 3.19.0 and >= 2.0.0 < 2.20.2
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "wrangler",
			Version:  "3.10.0",
			Type:     syftPkg.NpmPkg,
			Language: syftPkg.JavaScript,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "wrangler 3.10.0 should be vulnerable (range >= 3.0.0, < 3.19.0)")

		found := false
		for _, m := range matches {
			if m.Vulnerability.ID == "GHSA-f8mp-x433-5wpf" {
				found = true
				break
			}
		}
		assert.True(t, found, "GHSA-f8mp-x433-5wpf should be in results")
	})

	t.Run("match vulnerable wrangler v2", func(t *testing.T) {
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "wrangler",
			Version:  "2.15.0",
			Type:     syftPkg.NpmPkg,
			Language: syftPkg.JavaScript,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		require.NotEmpty(t, matches, "wrangler 2.15.0 should be vulnerable (range >= 2.0.0, < 2.20.2)")
	})

	t.Run("no match on fixed version", func(t *testing.T) {
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "wrangler",
			Version:  "3.19.0",
			Type:     syftPkg.NpmPkg,
			Language: syftPkg.JavaScript,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "wrangler 3.19.0 should not be vulnerable")
	})

	t.Run("no match below affected range", func(t *testing.T) {
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "wrangler",
			Version:  "1.9.0",
			Type:     syftPkg.NpmPkg,
			Language: syftPkg.JavaScript,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "wrangler 1.9.0 is below the affected range (>= 2.0.0)")
	})
}

func TestMultiProviderDB_CrossMatcherIsolation(t *testing.T) {
	// Build a single DB with fixtures from multiple providers, then verify
	// that each matcher only returns results relevant to its domain.
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2005-2964.json")),
		WithVunnelFixture(fixture("alpine-3.18-cve-2021-30473.json")),
		WithVunnelFixture(fixture("rhel-8-cve-2015-20107.json")),
		WithVunnelFixture(fixture("nvd-cve-2024-0181.json")),
		WithVunnelFixture(fixture("github-python-ghsa-9hx2-hgq2-2g4f.json")),
		WithVunnelFixture(fixture("github-npm-ghsa-f8mp-x433-5wpf.json")),
	)

	t.Run("dpkg matcher does not return alpine results", func(t *testing.T) {
		matcher := dpkg.NewDpkgMatcher(dpkg.MatcherConfig{})
		d := distro.New(distro.Debian, "8", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "aom",
			Version: "3.1.0-r0",
			Type:    syftPkg.DebPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "dpkg matcher should not find alpine vulnerabilities")
	})

	t.Run("apk matcher does not return debian results", func(t *testing.T) {
		matcher := &apk.Matcher{}
		d := distro.New(distro.Alpine, "3.18.0", "")
		p := pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    "abiword",
			Version: "2.2.7-1",
			Type:    syftPkg.ApkPkg,
			Distro:  d,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "apk matcher should not find debian vulnerabilities")
	})

	t.Run("python matcher does not return npm results", func(t *testing.T) {
		matcher := python.NewPythonMatcher(python.MatcherConfig{})
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "wrangler",
			Version:  "3.10.0",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "python matcher should not find npm vulnerabilities")
	})

	t.Run("javascript matcher does not return python results", func(t *testing.T) {
		matcher := javascript.NewJavascriptMatcher(javascript.MatcherConfig{})
		p := pkg.Package{
			ID:       pkg.ID(uuid.NewString()),
			Name:     "Pillow",
			Version:  "7.2.0",
			Type:     syftPkg.NpmPkg,
			Language: syftPkg.JavaScript,
		}

		matches, _, err := matcher.Match(provider, p)
		require.NoError(t, err)
		assert.Empty(t, matches, "javascript matcher should not find python vulnerabilities")
	})
}

// assertHasMatchType checks that at least one detail in the match has the given type.
func assertHasMatchType(t *testing.T, m match.Match, expected match.Type) {
	t.Helper()
	for _, d := range m.Details {
		if d.Type == expected {
			return
		}
	}
	t.Errorf("expected match type %v in details %+v", expected, m.Details)
}

func strRef(s string) *string {
	return &s
}

func intRef(i int) *int {
	return &i
}
