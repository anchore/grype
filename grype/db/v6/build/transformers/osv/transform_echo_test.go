package osv

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/osvmodel"
	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
	internalecho "github.com/anchore/grype/grype/internal/echo"
	"github.com/anchore/syft/syft/pkg"
)

// TestEchoTransform exercises the Echo language ecosystems supported by the
// strategy: PyPI, npm, Maven, and Go. Echo-patched builds use a "+echo.N"
// suffix; each record is emitted as a single UnaffectedPackageHandle (NAK)
// keyed by an internal Echo name and guarded by the Echo qualifier.
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
		{
			name:               "Echo Go module",
			fixturePath:        "testdata/ECHO-go-0001.json",
			pkgType:            pkg.GoModulePkg,
			expectedPkgName:    "golang.org/x/net",
			expectedCVE:        "CVE-2026-46600",
			expectedFixVersion: "v0.55.0+echo.1",
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
			require.Equal(tt, internalecho.PackageName(test.expectedPkgName), uph.Package.Name)
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

func TestEchoUnaffectedPackages_RejectsUnsafeRanges(t *testing.T) {
	tests := []struct {
		name string
		edit func(*osvmodel.Vulnerability)
		want int
	}{
		{
			name: "supported ecosystem range",
			edit: func(*osvmodel.Vulnerability) {},
			want: 1,
		},
		{
			name: "supported semver range is stored as ecosystem",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Type = osvmodel.RangeSemVer
			},
			want: 1,
		},
		{
			name: "missing range",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges = nil
			},
		},
		{
			name: "missing fix",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Events = v.Affected[0].Ranges[0].Events[:1]
			},
		},
		{
			name: "explicit versions list",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Versions = []string{"v0.55.0+echo.1"}
			},
		},
		{
			name: "fixed version must be an Echo build",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Events[1].Fixed = "v0.55.0"
			},
		},
		{
			name: "fixed version cannot contain a constraint",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Events[1].Fixed = "v0.55.0 || >=0+echo.1"
			},
		},
		{
			name: "last affected is not a safe open ended NAK",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Events[1] = osvmodel.Event{LastAffected: "v0.55.0"}
			},
		},
		{
			name: "reintroduced vulnerability window",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Events = append(
					v.Affected[0].Ranges[0].Events,
					osvmodel.Event{Introduced: "v0.55.1"},
				)
			},
		},
		{
			name: "multiple ranges",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges = append(v.Affected[0].Ranges, v.Affected[0].Ranges[0])
			},
		},
		{
			name: "duplicate package entries",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected = append(v.Affected, v.Affected[0])
			},
		},
		{
			name: "git range",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Ranges[0].Type = osvmodel.RangeGit
			},
		},
		{
			name: "noncanonical Maven name",
			edit: func(v *osvmodel.Vulnerability) {
				v.Affected[0].Package.Ecosystem = "Echo:Maven"
				v.Affected[0].Package.Name = "artifact"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := loadFixture(t, "testdata/ECHO-go-0001.json")
			require.Len(t, vulns, 1)
			vuln := &vulns[0]
			tt.edit(vuln)

			got := echoUnaffectedPackages(*vuln, vuln.Aliases)
			require.Len(t, got, tt.want)
			if tt.want > 0 {
				require.Len(t, got[0].BlobValue.Ranges, 1)
				require.Equal(t, "ecosystem", got[0].BlobValue.Ranges[0].Version.Type)
			}
		})
	}
}

func TestEchoPackage_EncodesNamesThatStartWithEcho(t *testing.T) {
	got := echoPackage(osvmodel.Package{
		Ecosystem: "Echo:Maven",
		Name:      "echo:artifact",
	}, pkg.JavaPkg)

	require.NotNil(t, got)
	require.Equal(t, "echo:echo:artifact", got.Name)

	require.Nil(t, echoPackage(osvmodel.Package{
		Ecosystem: "Echo:Maven",
		Name:      "artifact",
	}, pkg.JavaPkg))
}
