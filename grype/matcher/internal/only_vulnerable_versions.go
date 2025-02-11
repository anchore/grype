package internal

import (
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// onlyVulnerableVersion returns a criteria object that tests affected vulnerability ranges against the provided version
func onlyVulnerableVersions(v *version.Version) vulnerability.Criteria {
	if v == nil {
		// if no version is provided, match everything
		return search.ByFunc(func(_ vulnerability.Vulnerability) (bool, error) {
			return true, nil
		})
	}
	return search.ByVersion(*v)
}
