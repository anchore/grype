package internal

import (
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// onlyNonWithdrawnVulnerabilities returns a criteria object that tests affected vulnerability is not withdrawn/rejected
func onlyNonWithdrawnVulnerabilities() vulnerability.Criteria {
	return search.ByFunc(func(v vulnerability.Vulnerability) (bool, string, error) {
		// we should be using enumerations from all supported schema versions, but constants should not be imported here
		isWithdrawn := v.Status == "withdrawn" || v.Status == "rejected"
		if isWithdrawn {
			return false, "vulnerability is withdrawn or rejected", nil
		}
		return true, "", nil
	})
}
