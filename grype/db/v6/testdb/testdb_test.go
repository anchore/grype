package testdb

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

func fixture(name string) string {
	return filepath.Join(testdataDir(), name)
}

func TestNew_EmptyDB(t *testing.T) {
	// An empty DB (no fixtures) should still be usable — it has OS overrides
	// and ecosystem mappings but no vulnerability data.
	provider := New(t)

	vulns, err := provider.FindVulnerabilities()
	require.NoError(t, err)
	assert.Empty(t, vulns)
}

func TestNew_WithDebianFixture(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2005-2964.json")),
	)

	// Search by distro + package name — this exercises the real OS resolution
	// and package query SQL path.
	d := distro.New(distro.Debian, "8", "")
	vulns, err := provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("abiword"),
	)
	require.NoError(t, err)
	require.Len(t, vulns, 1, "expected exactly one vulnerability for abiword on debian:8")

	vuln := vulns[0]
	assert.Equal(t, "CVE-2005-2964", vuln.ID)
	assert.Equal(t, "abiword", vuln.PackageName)
	assert.Contains(t, vuln.Namespace, "debian")
}

func TestNew_WithDebianFixture_VersionFiltering(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2005-2964.json")),
	)

	d := distro.New(distro.Debian, "8", "")

	// Package version 1.0 should be vulnerable (fix is at 2.2.10-1)
	vulns, err := provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("abiword"),
		search.ByVersion(*version.New("1.0", version.DebFormat)),
	)
	require.NoError(t, err)
	assert.Len(t, vulns, 1, "version 1.0 should be vulnerable")

	// Package version 3.0 should NOT be vulnerable (fix is at 2.2.10-1)
	vulns, err = provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("abiword"),
		search.ByVersion(*version.New("3.0", version.DebFormat)),
	)
	require.NoError(t, err)
	assert.Empty(t, vulns, "version 3.0 should not be vulnerable")
}

func TestNew_WithAlpineFixture(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("alpine-3.18-cve-2021-30473.json")),
	)

	d := distro.New(distro.Alpine, "3.18.0", "")
	vulns, err := provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("aom"),
	)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2021-30473", vulns[0].ID)
}

func TestNew_WithNVDFixture_CPESearch(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("nvd-cve-2024-0181.json")),
	)

	// CPE search should find the NVD vulnerability via the CPE configurations
	// in the NVD record. This exercises the real CPE join SQL path.
	c := cpe.Must("cpe:2.3:a:nia:rrj_nueva_ecija_engineer_online_portal:1.0:*:*:*:*:*:*:*", "")
	vulns, err := provider.FindVulnerabilities(
		search.ByCPE(c),
	)
	require.NoError(t, err)
	require.NotEmpty(t, vulns, "should find CVE-2024-0181 via CPE search")

	found := false
	for _, v := range vulns {
		if v.ID == "CVE-2024-0181" {
			found = true
			break
		}
	}
	assert.True(t, found, "CVE-2024-0181 should be in results")
}

func TestNew_WithGitHubFixture_EcosystemSearch(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("github-python-ghsa-9hx2-hgq2-2g4f.json")),
	)

	// Language/ecosystem search — exercises the real ecosystem query path
	vulns, err := provider.FindVulnerabilities(
		search.ByEcosystem(syftPkg.Python, syftPkg.PythonPkg),
		search.ByPackageName("Pillow"),
	)
	require.NoError(t, err)
	require.NotEmpty(t, vulns, "should find GHSA for Pillow via ecosystem search")
}

func TestNew_WithMultipleFixtures(t *testing.T) {
	// A single DB can hold data from multiple providers — this is the normal
	// production scenario.
	provider := New(t,
		WithVunnelFixture(fixture("debian-8-cve-2005-2964.json")),
		WithVunnelFixture(fixture("alpine-3.18-cve-2021-30473.json")),
		WithVunnelFixture(fixture("github-python-ghsa-9hx2-hgq2-2g4f.json")),
	)

	// Debian query should only return debian results
	d := distro.New(distro.Debian, "8", "")
	vulns, err := provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("abiword"),
	)
	require.NoError(t, err)
	assert.Len(t, vulns, 1)

	// Alpine query should only return alpine results
	a := distro.New(distro.Alpine, "3.18.0", "")
	vulns, err = provider.FindVulnerabilities(
		search.ByDistro(*a),
		search.ByPackageName("aom"),
	)
	require.NoError(t, err)
	assert.Len(t, vulns, 1)

	// Python ecosystem query should only return GitHub advisory results
	vulns, err = provider.FindVulnerabilities(
		search.ByEcosystem(syftPkg.Python, syftPkg.PythonPkg),
		search.ByPackageName("Pillow"),
	)
	require.NoError(t, err)
	assert.NotEmpty(t, vulns)
}

func TestNew_WithRHELFixture(t *testing.T) {
	provider := New(t,
		WithVunnelFixture(fixture("rhel-8-cve-2015-20107.json")),
	)

	d := distro.New(distro.RedHat, "8", "")
	vulns, err := provider.FindVulnerabilities(
		search.ByDistro(*d),
		search.ByPackageName("python3"),
	)
	require.NoError(t, err)
	require.NotEmpty(t, vulns, "should find vulnerabilities for python3 on rhel:8")
}
