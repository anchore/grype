package upstreammatch

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// excludeFromUpstream keeps an entry out of the upstream (origin package) search. It is attached to entries
// whose provider publishes one entry per binary package, so an entry filed against an origin package
// describes that package only and must not reach the other packages built from the same origin.
type excludeFromUpstream struct{}

// New returns the upstreammatch qualifier. There is no per-instance state.
func New() qualifier.Qualifier {
	return excludeFromUpstream{}
}

// Satisfied is false for the copy UpstreamPackages builds to search an upstream package's entries, and true
// for every cataloged package, so the entry still matches the package it names.
func (excludeFromUpstream) Satisfied(p pkg.Package) (bool, error) {
	return !pkg.IsUpstreamSearch(p), nil
}

// Excludes reports whether a set of qualifiers contains the upstreammatch qualifier.
func Excludes(qualifiers []qualifier.Qualifier) bool {
	for _, q := range qualifiers {
		if _, ok := q.(excludeFromUpstream); ok {
			return true
		}
	}
	return false
}
