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
			name: "golang PURL keeps the module path",
			input: DBSearchPackages{
				Packages: []string{"pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "github.com/gin-gonic/gin", Ecosystem: "golang"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "github.com/gin-gonic/gin", TargetSW: "golang"}},
			},
		},
		{
			name: "npm scoped PURL keeps the scope",
			input: DBSearchPackages{
				Packages: []string{"pkg:npm/%40babel/core@7.0.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "@babel/core", Ecosystem: "npm"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "@babel/core", TargetSW: "npm"}},
			},
		},
		{
			name: "maven PURL joins group and artifact",
			input: DBSearchPackages{
				Packages: []string{"pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
			},
			expectedPkg: v6.PackageSpecifiers{
				{Name: "org.apache.commons:commons-lang3", Ecosystem: "maven"},
			},
			expectedCPE: v6.PackageSpecifiers{
				{CPE: &cpe.Attributes{Part: "a", Product: "org.apache.commons:commons-lang3", TargetSW: "maven"}},
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
