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
