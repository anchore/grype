package osv

import (
	"testing"

	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	"github.com/anchore/syft/syft/pkg"
)

// TestEchoTransform exercises the echo strategy against the three language
// ecosystems Echo publishes: PyPI, npm, and Maven. Echo ships patched builds of
// upstream packages with a "+echo.N" suffix; each record is emitted as a single
// UnaffectedPackageHandle (NAK) keyed by the UPSTREAM package name, with NO
// qualifier — the "+echo.N" version range scopes it on its own.
func TestEchoTransform(t *testing.T) {
	tests := []struct {
		name               string
		fixturePath        string
		pkgType            pkg.Type
		expectedPkgName    string
		expectedCVE        string
		expectedFixVersion string
	}{
		{
			name:               "Echo PyPI package",
			fixturePath:        "testdata/ECHO-pypi-0001.json",
			pkgType:            pkg.PythonPkg,
			expectedPkgName:    "requests",
			expectedCVE:        "CVE-2023-32681",
			expectedFixVersion: "2.14.2+echo.1",
		},
		{
			name:               "Echo npm package",
			fixturePath:        "testdata/ECHO-npm-0001.json",
			pkgType:            pkg.NpmPkg,
			expectedPkgName:    "ejs",
			expectedCVE:        "CVE-2022-29078",
			expectedFixVersion: "3.1.10+echo.1",
		},
		{
			name: "Echo Maven package",
			// JavaResolver.Normalize leaves groupId:artifactId verbatim.
			fixturePath:        "testdata/ECHO-maven-0001.json",
			pkgType:            pkg.JavaPkg,
			expectedPkgName:    "org.springframework:spring-web",
			expectedCVE:        "CVE-2024-22259",
			expectedFixVersion: "5.3.32+echo.1",
		},
	}

	for _, testToRun := range tests {
		test := testToRun
		t.Run(test.name, func(tt *testing.T) {
			vulns := loadFixture(tt, test.fixturePath)
			require.Len(tt, vulns, 1, "fixture should contain exactly one vulnerability")

			vuln := vulns[0]
			require.True(tt, echoStrategy{}.Matches(vuln.ID), "ID prefix should match the echo strategy")

			entries, err := Transform(vuln, inputProviderState())
			require.NoError(tt, err)
			require.Len(tt, entries, 1, "one RelatedEntries wrapping the vuln + unaffected handle")

			rel, ok := entries[0].Data.(transformers.RelatedEntries)
			require.True(tt, ok, "entry data should be RelatedEntries")

			require.NotNil(tt, rel.VulnerabilityHandle)
			require.Equal(tt, "osv", rel.VulnerabilityHandle.ProviderID)
			require.NotNil(tt, rel.VulnerabilityHandle.BlobValue)
			require.Contains(tt, rel.VulnerabilityHandle.BlobValue.Aliases, test.expectedCVE)

			require.Len(tt, rel.Related, 1, "echo emits exactly one unaffected package handle per language fixture")
			uph, ok := rel.Related[0].(db.UnaffectedPackageHandle)
			require.True(tt, ok, "related entry must be UnaffectedPackageHandle (NAK), not AffectedPackageHandle")

			require.NotNil(tt, uph.Package)
			require.Equal(tt, test.expectedPkgName, uph.Package.Name, "echo keeps the upstream package name (no prefix)")
			require.Equal(tt, test.pkgType.String(), uph.Package.Ecosystem)
			require.Nil(tt, uph.OperatingSystem, "language packages carry no OS metadata")

			require.NotNil(tt, uph.BlobValue)
			require.Contains(tt, uph.BlobValue.CVEs, test.expectedCVE)
			// The NAK must carry the Echo qualifier so suppression is gated to
			// actual Echo builds ("+echo.N"); without it the open-ended range
			// would leak onto plain higher upstream versions.
			require.NotNil(tt, uph.BlobValue.Qualifiers, "echo NAK must carry qualifiers")
			require.NotNil(tt, uph.BlobValue.Qualifiers.Echo, "Echo qualifier must be set")
			require.True(tt, *uph.BlobValue.Qualifiers.Echo)

			require.Len(tt, uph.BlobValue.Ranges, 1)
			constraint := uph.BlobValue.Ranges[0].Version.Constraint
			require.Contains(tt, constraint, ">=", "unaffected range constraint must use >= (versions at/above the echo fix are safe)")
			require.Contains(tt, constraint, test.expectedFixVersion)
		})
	}
}
