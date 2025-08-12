package internal

import (
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// OnlyVulnerableVersions returns a criteria object that tests affected vulnerability ranges against the provided version
func OnlyVulnerableVersions(v *version.Version) vulnerability.Criteria {
	if v == nil || v.Raw == "" {
		// if no version is provided, match everything
		return search.ByFunc(func(_ vulnerability.Vulnerability) (bool, string, error) {
			return true, "", nil
		}) // since we return true the summary is not used
	}
	return search.ByVersion(*v)
}
