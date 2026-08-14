package search

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

var _ vulnerability.Criteria = (*PackageVersionCriteria)(nil)

// PackageVersionCriteria conveys the version of the package a search is being performed for
// WITHOUT constraining the results to ranges that version satisfies — every record matches. Use
// it when the caller needs records on both sides of the version (both vulnerable and fixed, e.g.
// to build ignore rules from the fixed set) but the provider still needs the version to resolve
// where to search (e.g. search rules that route release streams by version
// markers). To constrain results by version, use ByVersion instead.
type PackageVersionCriteria struct {
	Version version.Version
}

// WithVersion returns criteria conveying the searched package's version without
// constraining results by it.
func WithVersion(v version.Version) vulnerability.Criteria {
	return &PackageVersionCriteria{Version: v}
}

func (v PackageVersionCriteria) MatchesVulnerability(_ vulnerability.Vulnerability) (bool, string, error) {
	return true, "", nil
}

func (v PackageVersionCriteria) Summarize() string {
	return "for package version: " + v.Version.Raw
}
