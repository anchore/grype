package internal

import (
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
)

// OnlyAffectedVulnerabilities returns a criteria object that filters out unaffected vulnerability records
func OnlyAffectedVulnerabilities() vulnerability.Criteria {
	return search.ByFunc(func(v vulnerability.Vulnerability) (bool, string, error) {
		if v.Unaffected {
			return false, "vulnerability is unaffected", nil
		}
		return true, "", nil
	})
}
