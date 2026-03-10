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
