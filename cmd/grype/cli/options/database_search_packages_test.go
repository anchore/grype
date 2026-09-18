package options

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/syft/syft/cpe"
)

func TestDBSearchPackagesPostLoad(t *testing.T) {
	testCases := []struct {
		name           string
		input          DBSearchPackages
		expectedPkg    v6.PackageSpecifiers
		expectedCPE    v6.PackageSpecifiers
		expectedErrMsg string
	}{
		{
			name: "valid CPE",
			input: DBSearchPackages{
				Packages: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor", Product: "product"}},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Vendor: "vendor", Product: "product"}},
			},
		},
		{
			name: "valid PURL",
			input: DBSearchPackages{
				Packages: []string{"pkg:npm/package-name@1.0.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "package-name", Ecosystem: "npm"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "package-name", TargetSW: "npm"}},
			},
		},
		{
			// the module path is split across namespace and name, and searching
			// for "gin" alone finds nothing
			name: "golang PURL keeps the full module path",
			input: DBSearchPackages{
				Packages: []string{"pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "github.com/gin-gonic/gin", Ecosystem: "golang"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "gin", TargetSW: "golang"}},
			},
		},
		{
			name: "scoped npm PURL keeps the scope",
			input: DBSearchPackages{
				Packages: []string{"pkg:npm/%40types/node@20.0.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "@types/node", Ecosystem: "npm"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "node", TargetSW: "npm"}},
			},
		},
		{
			// maven joins on a colon, matching grype/db/v6/name/java.go
			name: "maven PURL keeps the group",
			input: DBSearchPackages{
				Packages: []string{"pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "org.apache.commons:commons-lang3", Ecosystem: "maven"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "commons-lang3", TargetSW: "maven"}},
			},
		},
		{
			// the namespace on an rpm PURL is the distro, not part of the name
			name: "rpm PURL leaves the distro namespace out",
			input: DBSearchPackages{
				Packages: []string{"pkg:rpm/redhat/openssl@1.1.1k"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "openssl", Ecosystem: "rpm"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "openssl", TargetSW: "rpm"}},
			},
		},
		{
			name: "plain package name",
			input: DBSearchPackages{
				Packages: []string{"package-name"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "package-name"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "package-name"}},
			},
		},
		{
			name: "ecosystem without packages",
			input: DBSearchPackages{
				Ecosystem: "npm",
			},
			expectedPkg: v6.PackageSpecifiers{
				{Ecosystem: "npm"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{TargetSW: "npm"}},
			},
		},
		{
			name: "conflicting PURL and ecosystem",
			input: DBSearchPackages{
				Packages:  []string{"pkg:npm/package-name@1.0.0"},
				Ecosystem: "npm",
			},
			expectedErrMsg: "cannot specify both package URL and ecosystem",
		},
		{
			name: "invalid CPE",
			input: DBSearchPackages{
				Packages: []string{"cpe:2.3:a:$%&^*%"},
			},
			expectedErrMsg: "invalid CPE",
		},
		{
			name: "invalid PURL",
			input: DBSearchPackages{
				Packages: []string{"pkg:invalid"},
			},
			expectedErrMsg: "invalid package URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.PostLoad()

			if tc.expectedErrMsg != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.expectedErrMsg)
				return
			}
			require.NoError(t, err)
			if d := cmp.Diff(tc.expectedPkg, tc.input.PkgSpecs); d != "" {
				t.Errorf("unexpected package specifiers (-want +got):\n%s", d)
			}
			if d := cmp.Diff(tc.expectedCPE, tc.input.CPESpecs); d != "" {
				t.Errorf("unexpected CPE specifiers (-want +got):\n%s", d)
			}

		})
	}
}
