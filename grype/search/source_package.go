package search

import (
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*SourcePackageCriteria)(nil)

// SourcePackageCriteria marks a search for an upstream or source package, without constraining
// results; records found by it are indirect matches, even under the package's own name.
type SourcePackageCriteria struct{}

// BySourcePackage returns criteria marking a search for an upstream or source package.
func BySourcePackage() vulnerability.Criteria {
	return &SourcePackageCriteria{}
}

func (c SourcePackageCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (c SourcePackageCriteria) Summarize() string {
	return "for a source package"
}
