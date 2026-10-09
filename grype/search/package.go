package search

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*PackageCriteria)(nil)

// PackageCriteria states the package a search is for without constraining results, for
// providers that choose where to search by package (e.g. search rules). Pass the package actually
// searched: an upstream, a rootio name or an epoch-patched version, not the cataloged package.
type PackageCriteria struct {
	Package pkg.Package
}

// WithPackage returns criteria stating the searched package without constraining results.
func WithPackage(p pkg.Package) vulnerability.Criteria {
	return &PackageCriteria{Package: p}
}

func (c PackageCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (c PackageCriteria) Summarize() string {
	return "for package: " + c.Package.Name + "@" + c.Package.Version
}
