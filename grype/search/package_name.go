package search

import (
	"strings"

	"github.com/anchore/grype/grype/vulnerability"
)

// ByPackageName returns criteria restricting vulnerabilities to match the package name provided
func ByPackageName(name string) vulnerability.Criteria {
	return &PackageNameCriteria{
		PackageName: name,
	}
}

// ByPackageNames returns criteria restricting vulnerabilities to match any of the package names provided
func ByPackageNames(names ...string) vulnerability.Criteria {
	return byMany(ByPackageName, names...)
}

type PackageNameCriteria struct {
	PackageName string
}

func (v *PackageNameCriteria) MatchesVulnerability(vuln vulnerability.Vulnerability) (bool, error) {
	return strings.EqualFold(vuln.PackageName, v.PackageName), nil
}

var _ interface {
	vulnerability.Criteria
} = (*PackageNameCriteria)(nil)
