package search

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/vulnerability"
)

// ByPackageName returns criteria restricting vulnerabilities to match the package name provided
func ByPackageName(packageName string) vulnerability.Criteria {
	return &PackageNameCriteria{
		PackageName: packageName,
	}
}

type PackageNameCriteria struct {
	PackageName string
}

func (v *PackageNameCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, string, error) {
	matchesPackageName := strings.EqualFold(vuln.PackageName, v.PackageName)
	if !matchesPackageName {
		return false, fmt.Sprintf("vulnerability package name %q does not match expected package name %q", vuln.PackageName, v.PackageName), nil
	}
	return true, "", nil
}

var _ interface {
	vulnerability.Criteria
} = (*PackageNameCriteria)(nil)

// ByPackageNamePrefix returns criteria restricting vulnerabilities to those whose package name
// begins with the provided prefix followed by a "/" path-segment boundary. This is intended for
// ecosystems (such as Go modules) where an advisory may be filed at an import-path granularity
// inside a larger module while the SBOM only carries the module path. The boundary check ensures
// the prefix only matches when the advisory name represents an import path strictly under the
// supplied module: prefix "golang.org/x/crypto" matches "golang.org/x/crypto/ssh" but not
// "golang.org/x/cryptographer".
func ByPackageNamePrefix(prefix string) vulnerability.Criteria {
	return &PackageNamePrefixCriteria{
		PackageNamePrefix: prefix,
	}
}

type PackageNamePrefixCriteria struct {
	PackageNamePrefix string
}

func (v *PackageNamePrefixCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, string, error) {
	if v.PackageNamePrefix == "" {
		return false, "empty package name prefix", nil
	}
	prefix := strings.ToLower(v.PackageNamePrefix) + "/"
	if !strings.HasPrefix(strings.ToLower(vuln.PackageName), prefix) {
		return false, fmt.Sprintf("vulnerability package name %q does not start with expected prefix %q", vuln.PackageName, v.PackageNamePrefix+"/"), nil
	}
	return true, "", nil
}

var _ interface {
	vulnerability.Criteria
} = (*PackageNamePrefixCriteria)(nil)
