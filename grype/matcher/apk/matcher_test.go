package apk

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/v6/testdb"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestSecDBOnlyMatch(t *testing.T) {
	// Uses real alpine secDB fixture for CVE-2021-30473 (aom, fix at 3.1.1-r0)
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/alpine-3.18-cve-2021-30473.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.18.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "aom",
		Version: "3.1.0-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.0:*:*:*:*:*:*:*", ""),
		},
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)
	require.Len(t, actual, 1, "expected one secDB match for aom")

	assert.Equal(t, "CVE-2021-30473", actual[0].Vulnerability.ID)
	assert.Equal(t, "aom", actual[0].Package.Name)
	require.NotEmpty(t, actual[0].Details)
	assert.Equal(t, match.ExactDirectMatch, actual[0].Details[0].Type)
	assert.Equal(t, match.ApkMatcher, actual[0].Details[0].Matcher)
}

func TestBothSecdbAndNvdMatches(t *testing.T) {
	// Both Alpine secDB and NVD have CVE-2021-30473 for aom/aomedia.
	// The APK matcher should deduplicate: secDB match preferred over NVD.
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/alpine-3.18-cve-2021-30473.json"),
		testdb.WithVunnelFixture("testdata/nvd-cve-2021-30473.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.18.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "aom",
		Version: "3.1.0-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.0:*:*:*:*:*:*:*", ""),
		},
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)

	// Should have exactly one match for CVE-2021-30473 (deduplicated)
	cveMatches := filterByVulnID(actual, "CVE-2021-30473")
	require.Len(t, cveMatches, 1, "secDB and NVD should be deduplicated to one match")

	// The secDB (distro) match should be preferred over the NVD (CPE) match
	require.NotEmpty(t, cveMatches[0].Details)
	assert.Equal(t, match.ExactDirectMatch, cveMatches[0].Details[0].Type,
		"secDB match (direct) should be preferred over NVD (CPE)")
}

func TestBothSecdbAndNvdMatches_DifferentFixInfo(t *testing.T) {
	// Both Alpine secDB and NVD have CVE-2021-30473. The secDB fix (3.1.1-r0)
	// should be authoritative over NVD fix info.
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/alpine-3.18-cve-2021-30473.json"),
		testdb.WithVunnelFixture("testdata/nvd-cve-2021-30473.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.18.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "aom",
		Version: "3.1.0-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.0:*:*:*:*:*:*:*", ""),
		},
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)

	cveMatches := filterByVulnID(actual, "CVE-2021-30473")
	require.Len(t, cveMatches, 1, "should be deduplicated")

	// The secDB match should carry fix info from the alpine source
	assert.NotEmpty(t, cveMatches[0].Vulnerability.Fix.Versions,
		"secDB match should have fix version info")
}

func TestBothSecdbAndNvdMatches_DifferentPackageName(t *testing.T) {
	// NVD and Alpine's secDB both have the same CVE ID for the package,
	// but the NVD CPE product name differs from the package name.
	// This is a synthetic edge case that's hard to reproduce with real data.
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		// Note: the product name is NOT the same as the target package name
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:lib_vnc_project-(server):libvncumbrellaproject:*:*:*:*:*:*:*:*", ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			// Note: the product name is NOT the same as the package name
			cpe.Must("cpe:2.3:a:*:libvncumbrellaproject:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			// ensure the SECDB record is preferred over the NVD record
			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactDirectMatch,
					Confidence: 1.0,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    d.Type.String(),
							Version: d.Version,
						},
						Package: match.PackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
						Namespace: "secdb:distro:alpine:3.12",
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2020-1",
						VersionConstraint: secDbVuln.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches(t *testing.T) {
	// Tests NVD-only match with special characters in CPE names.
	// Kept as mock because the CPE escaping edge case is hard to reproduce with real data.
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):lib/vncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:lib/vncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{

			Vulnerability: nvdVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:lib\\/vncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.PackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: match.CPEResult{
						// use .String() for proper escaping
						CPEs:              []string{nvdVuln.CPEs[0].Attributes.String()},
						VersionConstraint: nvdVuln.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdOnlyMatches_FixInNvd(t *testing.T) {
	// Tests that NVD fix info is stripped for Alpine CPE matches.
	// Kept as mock for exact fix-stripping assertion.
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
		Fix: vulnerability.Fix{
			Versions: []string{"0.9.12"},
			State:    vulnerability.FixStateFixed,
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.9",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	vulnFound := nvdVuln
	// Important: for alpine matcher, fix version can come from secDB but _not_ from
	// NVD data.
	vulnFound.Fix = vulnerability.Fix{State: vulnerability.FixStateUnknown}

	expected := []match.Match{
		{
			Vulnerability: vulnFound,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.PackageParameter{
							Name:    "libvncserver",
							Version: "0.9.9",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{vulnFound.CPEs[0].Attributes.String()},
						VersionConstraint: vulnFound.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesProperVersionFiltering(t *testing.T) {
	// Tests that version boundary filtering works correctly with two NVD records:
	// one matching (<= 0.9.11) and one not (< 0.9.11) for version 0.9.11-r10.
	// Kept as mock because this exact boundary scenario needs controlled data.
	nvdVulnMatch := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("<= 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	nvdVulnNoMatch := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-2",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVulnMatch, nvdVulnNoMatch)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11-r10",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*", ""),
		},
	}

	expected := []match.Match{
		{
			Vulnerability: nvdVulnMatch,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:*:libvncserver:0.9.11:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.PackageParameter{
							Name:    "libvncserver",
							Version: "0.9.11-r10",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{nvdVulnMatch.CPEs[0].Attributes.String()},
						VersionConstraint: nvdVulnMatch.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNvdMatchesWithSecDBFix(t *testing.T) {
	// When secDB says a version is fixed, NVD matches should be canceled
	// even if the NVD constraint would still match.
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/alpine-3.18-cve-2021-30473.json"),
		testdb.WithVunnelFixture("testdata/nvd-cve-2021-30473.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.18.0", "")

	// Use the secDB fix version - should NOT be vulnerable
	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "aom",
		Version: "3.1.1-r0", // this is the fix version per alpine secDB
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:aomedia:aomedia:3.1.1:*:*:*:*:*:*:*", ""),
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	// secDB says 3.1.1-r0 is the fix — no match, even if NVD range would include it
	assert.Empty(t, actual, "version at secDB fix should not match")
}

func TestNvdMatchesNoConstraintWithSecDBFix(t *testing.T) {
	// Tests that an NVD record with empty constraint (all versions vulnerable)
	// is still canceled by a secDB fix. Kept as mock for the empty constraint case.
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("", version.UnknownFormat), // note: empty value indicates that all versions are vulnerable
		CPEs: []cpe.CPE{
			cpe.Must(`cpe:2.3:a:lib_vnc_project-\(server\):libvncserver:*:*:*:*:*:*:*:*`, ""),
		},
	}

	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "libvncserver",
		Constraint:  version.MustGetConstraint("< 0.9.11", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(nvdVuln, secDbVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "libvncserver",
		Version: "0.9.11",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:*:libvncserver:0.9.9:*:*:*:*:*:*:*", ""),
		},
	}

	var expected []match.Match

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchCanceledByOriginPackageInSecDB(t *testing.T) {
	// A wolfi NAK entry (fix "< 0") for an upstream package should cancel
	// NVD CPE matches for a downstream package.
	// Uses real wolfi fixture for CVE-2015-3211 (php-8.3 NAK).
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/wolfi-rolling-cve-2015-3211.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Wolfi, "", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "php-8.3-fpm",
		Version: "8.3.11-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:php-fpm:php-fpm:8.3.11-r0:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name:    "php-8.3",
				Version: "8.3.11-r0",
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	// The NAK entry should prevent any match for CVE-2015-3211
	for _, a := range actual {
		assert.NotEqual(t, "CVE-2015-3211", a.Vulnerability.ID,
			"NAK entry should cancel matches for this CVE")
	}
}

func TestDistroMatchBySourceIndirection(t *testing.T) {
	// Uses real alpine fixture. A package "aom-libs" with upstream "aom"
	// should match CVE-2021-30473 via source indirection.
	vp := testdb.New(t,
		testdb.WithVunnelFixture("testdata/alpine-3.18-cve-2021-30473.json"),
	)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.18.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "aom-libs",
		Version: "3.1.0-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "aom",
			},
		},
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:aom-libs:aom-libs:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
		},
	}

	actual, _, err := m.Match(vp, p)
	require.NoError(t, err)
	require.Len(t, actual, 1, "expected one indirect match via upstream aom")

	assert.Equal(t, "CVE-2021-30473", actual[0].Vulnerability.ID)
	assert.Equal(t, "aom-libs", actual[0].Package.Name, "match should report the original package name")
	require.NotEmpty(t, actual[0].Details)
	assert.Equal(t, match.ExactIndirectMatch, actual[0].Details[0].Type)
	assert.Equal(t, match.ApkMatcher, actual[0].Details[0].Matcher)
}

func TestSecDBMatchesStillCountedWithCpeErrors(t *testing.T) {
	// Tests that secDB matches still work even when CPE processing errors occur.
	// Kept as mock because it tests error resilience, not data correctness.
	secDbVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-2",
			Namespace: "secdb:distro:alpine:3.12",
		},
		PackageName: "musl",
		Constraint:  version.MustGetConstraint("<= 1.3.3-r0", version.ApkFormat),
	}

	vp := mock.VulnerabilityProvider(secDbVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
		CPEs: []cpe.CPE{},
	}

	expected := []match.Match{
		{

			Vulnerability: secDbVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.ExactIndirectMatch,
					Confidence: 1.0,
					SearchedBy: match.DistroParameters{
						Distro: match.DistroIdentification{
							Type:    d.Type.String(),
							Version: d.Version,
						},
						Package: match.PackageParameter{
							Name:    "musl",
							Version: p.Version,
						},
						Namespace: "secdb:distro:alpine:3.12",
					},
					Found: match.DistroResult{
						VulnerabilityID:   "CVE-2020-2",
						VersionConstraint: secDbVuln.Constraint.String(),
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func TestNVDMatchBySourceIndirection(t *testing.T) {
	// Tests NVD CPE match via upstream package with specific CPE generation.
	// Kept as mock for the specific CPE upstream matching scenario.
	nvdVuln := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{
			ID:        "CVE-2020-1",
			Namespace: "nvd:cpe",
		},
		PackageName: "musl",
		Constraint:  version.MustGetConstraint("<= 1.3.3-r0", version.UnknownFormat),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl:musl:*:*:*:*:*:*:*:*", ""),
		},
	}
	vp := mock.VulnerabilityProvider(nvdVuln)

	m := Matcher{}
	d := distro.New(distro.Alpine, "3.12.0", "")

	p := pkg.Package{
		ID:      pkg.ID(uuid.NewString()),
		Name:    "musl-utils",
		Version: "1.3.2-r0",
		Type:    syftPkg.ApkPkg,
		Distro:  d,
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
			cpe.Must("cpe:2.3:a:musl-utils:musl-utils:*:*:*:*:*:*:*:*", ""),
		},
		Upstreams: []pkg.UpstreamPackage{
			{
				Name: "musl",
			},
		},
	}

	expected := []match.Match{
		{
			Vulnerability: nvdVuln,
			Package:       p,
			Details: []match.Detail{
				{
					Type:       match.CPEMatch,
					Confidence: 0.9,
					SearchedBy: match.CPEParameters{
						CPEs:      []string{"cpe:2.3:a:musl:musl:1.3.2-r0:*:*:*:*:*:*:*"},
						Namespace: "nvd:cpe",
						Package: match.PackageParameter{
							Name:    "musl",
							Version: "1.3.2-r0",
						},
					},
					Found: match.CPEResult{
						CPEs:              []string{nvdVuln.CPEs[0].Attributes.String()},
						VersionConstraint: nvdVuln.Constraint.String(),
						VulnerabilityID:   "CVE-2020-1",
					},
					Matcher: match.ApkMatcher,
				},
			},
		},
	}

	actual, _, err := m.Match(vp, p)
	assert.NoError(t, err)

	assertMatches(t, expected, actual)
}

func assertMatches(t *testing.T, expected, actual []match.Match) {
	t.Helper()
	var opts = []cmp.Option{
		cmpopts.IgnoreFields(vulnerability.Vulnerability{}, "Constraint"),
		cmpopts.IgnoreFields(pkg.Package{}, "Locations"),
		cmpopts.IgnoreUnexported(distro.Distro{}),
	}

	if diff := cmp.Diff(expected, actual, opts...); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

func filterByVulnID(matches []match.Match, id string) []match.Match {
	var result []match.Match
	for _, m := range matches {
		if m.Vulnerability.ID == id {
			result = append(result, m)
		}
	}
	return result
}

func Test_nakConstraint(t *testing.T) {
	tests := []struct {
		name    string
		input   vulnerability.Vulnerability
		wantErr require.ErrorAssertionFunc
		matches bool
	}{
		{
			name: "matches apk",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.ApkFormat),
			},
			matches: true,
		},
		{
			name: "not match due to type",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 0", version.SemanticFormat),
			},
			matches: false,
		},
		{
			name: "not match",
			input: vulnerability.Vulnerability{
				Constraint: version.MustGetConstraint("< 2.0", version.SemanticFormat),
			},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			matches, _, err := nakConstraint.MatchesVulnerability(tt.input)
			tt.wantErr(t, err)
			require.Equal(t, tt.matches, matches)
		})
	}
}

func Test_nakIgnoreRules(t *testing.T) {
	// NAK ignore rule tests use synthetic data with fake package names,
	// which is appropriate for testing the ignore rule generation logic.
	cases := []struct {
		name                    string
		pkgs                    []pkg.Package
		vulns                   []vulnerability.Vulnerability
		expectedLocationIgnores map[string][]string
		errAssertion            assert.ErrorAssertionFunc
	}{
		{
			name: "false positive in wolfi package adds index entry",
			pkgs: []pkg.Package{
				{
					Name:   "foo",
					Distro: &distro.Distro{Type: distro.Wolfi},
					Metadata: pkg.ApkMetadata{Files: []pkg.ApkFileRecord{
						{
							Path: "/bin/foo-binary",
						},
					}},
				},
			},
			vulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "GHSA-2014-fake-3",
						Namespace: "wolfi:distro:wolfi:rolling",
					},
					PackageName: "foo",
					Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
				},
			},
			expectedLocationIgnores: map[string][]string{
				"/bin/foo-binary": {"GHSA-2014-fake-3"},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "false positive in wolfi subpackage adds index entry",
			pkgs: []pkg.Package{
				{
					Name:   "subpackage-foo",
					Distro: &distro.Distro{Type: distro.Wolfi},
					Metadata: pkg.ApkMetadata{Files: []pkg.ApkFileRecord{
						{
							Path: "/bin/foo-subpackage-binary",
						},
					}},
					Upstreams: []pkg.UpstreamPackage{
						{
							Name: "origin-foo",
						},
					},
				},
			},
			vulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "GHSA-2014-fake-3",
						Namespace: "wolfi:distro:wolfi:rolling",
					},
					PackageName: "origin-foo",
					Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
				},
			},
			expectedLocationIgnores: map[string][]string{
				"/bin/foo-subpackage-binary": {"GHSA-2014-fake-3"},
			},
			errAssertion: assert.NoError,
		},
		{
			name: "fixed vuln (not a false positive) in wolfi package",
			pkgs: []pkg.Package{
				{
					Name:   "foo",
					Distro: &distro.Distro{Type: distro.Wolfi},
					Metadata: pkg.ApkMetadata{Files: []pkg.ApkFileRecord{
						{
							Path: "/bin/foo-binary",
						},
					}},
				},
			},
			vulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "GHSA-2014-fake-3",
						Namespace: "wolfi:distro:wolfi:rolling",
					},
					PackageName: "foo",
					Constraint:  version.MustGetConstraint("< 1.2.3-r4", version.ApkFormat),
				},
			},
			expectedLocationIgnores: map[string][]string{},
			errAssertion:            assert.NoError,
		},
		{
			name: "no vuln data for wolfi package",
			pkgs: []pkg.Package{
				{
					Name:   "foo",
					Distro: &distro.Distro{Type: distro.Wolfi},
					Metadata: pkg.ApkMetadata{Files: []pkg.ApkFileRecord{
						{
							Path: "/bin/foo-binary",
						},
					}},
				},
			},
			vulns:                   []vulnerability.Vulnerability{},
			expectedLocationIgnores: map[string][]string{},
			errAssertion:            assert.NoError,
		},
		{
			name: "no files listed for a wolfi package",
			pkgs: []pkg.Package{
				{
					Name:     "foo",
					Distro:   &distro.Distro{Type: distro.Wolfi},
					Metadata: pkg.ApkMetadata{Files: nil},
				},
			},
			vulns: []vulnerability.Vulnerability{
				{
					Reference: vulnerability.Reference{
						ID:        "GHSA-2014-fake-3",
						Namespace: "wolfi:distro:wolfi:rolling",
					},
					PackageName: "foo",
					Constraint:  version.MustGetConstraint("< 0", version.ApkFormat),
				},
			},
			expectedLocationIgnores: map[string][]string{},
			errAssertion:            assert.NoError,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// create mock vulnerability provider
			vp := mock.VulnerabilityProvider(tt.vulns...)
			apkMatcher := &Matcher{}

			var allMatches []match.Match
			var allIgnores []match.IgnoreFilter
			for _, p := range tt.pkgs {
				matches, ignores, err := apkMatcher.Match(vp, p)
				require.NoError(t, err)
				allMatches = append(allMatches, matches...)
				allIgnores = append(allIgnores, ignores...)
			}

			actualResult := map[string][]string{}
			for _, ignore := range allIgnores {
				rule, ok := ignore.(match.IgnoreRule)
				if !ok {
					require.Fail(t, "expected ignore to be of type IgnoreRule")
				}
				if rule.Package.Location == "" {
					require.Fail(t, "expected package location to be set in ignore rule")
				}
				actualResult[rule.Package.Location] = append(actualResult[rule.Package.Location], rule.Vulnerability)
			}
			require.Equal(t, tt.expectedLocationIgnores, actualResult)
		})
	}
}
