package internal

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// onlyQualifiedPackages returns a criteria object that tests vulnerability qualifiers against the provided package
func onlyQualifiedPackages(p pkg.Package) vulnerability.Criteria {
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, error) {
		for _, qualifier := range vuln.PackageQualifiers {
			satisfied, err := qualifier.Satisfied(p)
			if err != nil {
				return satisfied, err
			}
			if !satisfied {
				return false, nil
			}
		}
		return true, nil // all qualifiers passed
	})
}
