package rpm

import (
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

const rpmFIPSSuffix = "_fips"

// onlyMatchingFIPSSuffix suppresses matches where a FIPS stream-suffix
// mismatch between the vulnerability's fix version and the installed package
// would produce a false positive (or false negative).
//
// Oracle Linux ships FIPS builds with epoch 10 and a "_fips" release suffix
// (e.g. 10:3.0.7-28.0.1.el9_4_fips). Because epoch 10 > epoch 1, every
// standard non-FIPS package at epoch 0 or 1 would otherwise appear
// permanently vulnerable to every ELSA FIPS advisory — the installed version
// can never satisfy the fix constraint because the epochs are from different
// package streams entirely.
//
// The filter is symmetric: a FIPS-build package will also not match a
// standard-stream advisory whose fix version carries no "_fips" suffix.
func onlyMatchingFIPSSuffix(p pkg.Package) vulnerability.Criteria {
	pkgHasFIPS := hasFIPSSuffix(p.Version)
	return search.ByFunc(func(vuln vulnerability.Vulnerability) (bool, string, error) {
		vulnHasFIPS := false
		for _, fixVersion := range vuln.Fix.Versions {
			if hasFIPSSuffix(fixVersion) {
				vulnHasFIPS = true
				break
			}
		}
		// Fall back to the constraint string when Fix.Versions is not populated
		// (some DB records encode the fix only in the constraint expression).
		if !vulnHasFIPS && vuln.Constraint != nil {
			vulnHasFIPS = hasFIPSSuffix(vuln.Constraint.Value())
		}
		if vulnHasFIPS == pkgHasFIPS {
			return true, "", nil
		}
		return false, "FIPS release-suffix mismatch between package and vulnerability fix version", nil
	})
}

func hasFIPSSuffix(v string) bool {
	return strings.Contains(v, rpmFIPSSuffix)
}
