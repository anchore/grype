package internal

import (
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// onlyVulnerableVersion returns a criteria object that tests affected vulnerability ranges against the provided version
func onlyVulnerableVersions(v *version.Version) vulnerability.Criteria {
	return search.ByVersion(*v)
}
