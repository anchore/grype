package osv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal"
	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/syft/syft/pkg"
)

// TestLightwellTransform exercises the lightwell strategy against real
// records from github.com/project-lightwell/lightwell-osv, covering each
// remediation suffix shape and the multi-CVE release:
//
//   - woodstox-core: Maven, dot-separated suffix (6.0.3.rhlw-00001)
//   - spring-expression: Maven, one release backporting many CVEs
//   - netty-handler-proxy: Maven, dash-separated suffix (4.1.100.Final-rhlw-00001)
//   - thymeleaf: backport_base_version upstream holds the remediated version
//     itself, so the base must come from the fixed version's suffix
//   - pypdf2: PyPI local version suffix (3.0.1+rhlw.1)
//
// Each test confirms: the vulnerability carries every `upstream` ID in its
// aliases, exactly one UnaffectedPackageHandle is produced (NAK semantics)
// with the upstream package coordinates and ecosystem format, the
// LightwellBaseVersion qualifier pins the build line, and the unaffected
// constraint is ">=" the remediated build.
func TestLightwellTransform(t *testing.T) {
	tests := []struct {
		name                string
		fixturePath         string
		expectedEcosystem   string
		expectedPkgName     string
		expectedUpstream    []string
		expectedFixVersion  string
		expectedBaseVersion string
		expectedVersionType string
	}{
		{
			name:                "Maven dot-separated suffix",
			fixturePath:         "testdata/RHLW-2026-403d1e66c95ef9bb.json",
			expectedEcosystem:   pkg.JavaPkg.String(),
			expectedPkgName:     "com.fasterxml.woodstox:woodstox-core",
			expectedUpstream:    []string{"CVE-2022-40152", "GHSA-3f7h-mf4q-vrm4"},
			expectedFixVersion:  "6.0.3.rhlw-00001",
			expectedBaseVersion: "6.0.3",
			expectedVersionType: "maven",
		},
		{
			name:                "Maven multi-CVE release",
			fixturePath:         "testdata/RHLW-2026-25544e781d50b856.json",
			expectedEcosystem:   pkg.JavaPkg.String(),
			expectedPkgName:     "org.springframework:spring-expression",
			expectedUpstream:    []string{"CVE-2023-20861", "CVE-2024-38808", "CVE-2025-41249", "GHSA-jmp9-x22r-554x"},
			expectedFixVersion:  "5.3.18.rhlw-00010",
			expectedBaseVersion: "5.3.18",
			expectedVersionType: "maven",
		},
		{
			name:                "Maven dash-separated suffix",
			fixturePath:         "testdata/RHLW-2026-05e60f2154dee59a.json",
			expectedEcosystem:   pkg.JavaPkg.String(),
			expectedPkgName:     "io.netty:netty-handler-proxy",
			expectedFixVersion:  "4.1.100.Final-rhlw-00001",
			expectedBaseVersion: "4.1.100.Final",
			expectedVersionType: "maven",
		},
		{
			name:                "base version derived from fixed version, not backport_base_version",
			fixturePath:         "testdata/RHLW-2026-e0e5640c50ceea84.json",
			expectedEcosystem:   pkg.JavaPkg.String(),
			expectedPkgName:     "org.thymeleaf:thymeleaf",
			expectedFixVersion:  "3.0.15.RELEASE-rhlw-00009",
			expectedBaseVersion: "3.0.15.RELEASE",
			expectedVersionType: "maven",
		},
		{
			name:                "PyPI local version suffix",
			fixturePath:         "testdata/RHLW-2026-821eaab8409c2a61.json",
			expectedEcosystem:   pkg.PythonPkg.String(),
			expectedPkgName:     "pypdf2",
			expectedFixVersion:  "3.0.1+rhlw.1",
			expectedBaseVersion: "3.0.1",
			expectedVersionType: "python",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vulns := loadFixture(t, test.fixturePath)
			require.Len(t, vulns, 1, "fixture should contain exactly one vulnerability")

			vuln := vulns[0]
			require.True(t, lightwellStrategy{}.Matches(vuln.ID), "ID prefix should match the lightwell strategy")

			entries, err := Transform(vuln, inputProviderState())
			require.NoError(t, err)
			require.Len(t, entries, 1, "one RelatedEntries wrapping the vuln + unaffected handle(s)")

			rel, ok := entries[0].Data.(transformers.RelatedEntries)
			require.True(t, ok, "entry data should be RelatedEntries")

			require.NotNil(t, rel.VulnerabilityHandle)
			require.NotNil(t, rel.VulnerabilityHandle.BlobValue)
			require.Equal(t, vuln.ID, rel.VulnerabilityHandle.Name)
			require.NotEmpty(t, vuln.Upstream)
			require.Subset(t, rel.VulnerabilityHandle.BlobValue.Aliases, vuln.Upstream)
			require.Subset(t, rel.VulnerabilityHandle.BlobValue.Aliases, test.expectedUpstream)
			for _, ref := range rel.VulnerabilityHandle.BlobValue.References {
				require.Empty(t, ref.ID, "lightwell ADVISORY references point at upstream pages, not at the lightwell advisory")
			}

			require.Len(t, rel.Related, 1, "lightwell NAK emits exactly one unaffected package handle per fixture")
			uph, ok := rel.Related[0].(db.UnaffectedPackageHandle)
			require.True(t, ok, "related entry must be UnaffectedPackageHandle (NAK), not AffectedPackageHandle")

			require.NotNil(t, uph.Package)
			require.Equal(t, test.expectedEcosystem, uph.Package.Ecosystem)
			require.Equal(t, test.expectedPkgName, uph.Package.Name)
			require.Nil(t, uph.OperatingSystem)

			require.NotNil(t, uph.BlobValue)
			require.Subset(t, uph.BlobValue.CVEs, vuln.Upstream,
				"NAK CVEs must include every upstream ID so the matcher's identity-match removes the upstream disclosure")

			require.NotNil(t, uph.BlobValue.Qualifiers)
			require.NotNil(t, uph.BlobValue.Qualifiers.LightwellBaseVersion)
			require.Equal(t, test.expectedBaseVersion, *uph.BlobValue.Qualifiers.LightwellBaseVersion)

			require.Len(t, uph.BlobValue.Ranges, 1)
			require.Equal(t, test.expectedVersionType, uph.BlobValue.Ranges[0].Version.Type)
			require.Equal(t, ">= "+test.expectedFixVersion, uph.BlobValue.Ranges[0].Version.Constraint)
		})
	}
}

func TestLightwellTransform_SkipsUnusableAffectedEntries(t *testing.T) {
	fixedRange := func(fixed string) []osvmodel.Range {
		return []osvmodel.Range{{
			Type:   osvmodel.RangeEcosystem,
			Events: []osvmodel.Event{{Introduced: "0"}, {Fixed: fixed}},
		}}
	}

	vuln := unmarshal.OSVVulnerability{}
	vuln.ID = "RHLW-2026-0000000000000000"
	vuln.Upstream = []string{"CVE-2024-0001"}
	vuln.Affected = []osvmodel.Affected{
		{
			// unsupported ecosystem
			Package: osvmodel.Package{Ecosystem: "Red Hat Lightwell:npm", Name: "left-pad"},
			Ranges:  fixedRange("1.3.0-rhlw-00001"),
		},
		{
			// not a scoped Lightwell ecosystem
			Package: osvmodel.Package{Ecosystem: "Maven", Name: "org.example:lib"},
			Ranges:  fixedRange("1.0.0.rhlw-00001"),
		},
		{
			// no suffix on the fix and no backport_base_version: no line to pin to
			Package: osvmodel.Package{Ecosystem: "Red Hat Lightwell:Maven", Name: "org.example:lib"},
			Ranges:  fixedRange("1.0.1"),
		},
		{
			// no suffix on the fix, but backport_base_version is present
			Package: osvmodel.Package{Ecosystem: "Red Hat Lightwell:Maven", Name: "org.example:other"},
			Ranges:  fixedRange("2.0.0.1"),
			DatabaseSpecific: map[string]any{
				"lightwell": map[string]any{"backport_base_version": "2.0.0"},
			},
		},
	}

	entries, err := Transform(vuln, inputProviderState())
	require.NoError(t, err)
	require.Len(t, entries, 1)

	rel, ok := entries[0].Data.(transformers.RelatedEntries)
	require.True(t, ok)
	require.Len(t, rel.Related, 1, "only the entry with a supported ecosystem and a determinable base version is kept")

	uph, ok := rel.Related[0].(db.UnaffectedPackageHandle)
	require.True(t, ok)
	require.Equal(t, "org.example:other", uph.Package.Name)
	require.Equal(t, "2.0.0", *uph.BlobValue.Qualifiers.LightwellBaseVersion)
}

func TestLightwellPackageType(t *testing.T) {
	tests := []struct {
		ecosystem string
		want      pkg.Type
	}{
		{ecosystem: "Red Hat Lightwell:Maven", want: pkg.JavaPkg},
		{ecosystem: "Red Hat Lightwell:PyPI", want: pkg.PythonPkg},
		{ecosystem: "Red Hat Lightwell:npm", want: ""},
		{ecosystem: "Maven", want: ""},
		{ecosystem: "Red Hat:Maven", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.ecosystem, func(t *testing.T) {
			require.Equal(t, tt.want, lightwellPackageType(tt.ecosystem))
		})
	}
}
