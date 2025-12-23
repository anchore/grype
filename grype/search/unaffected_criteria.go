package search

import "github.com/anchore/grype/grype/vulnerability"

type OSSpecifierProvider interface {
	vulnerability.Criteria
	GetOSSpecifier() (name, major, minor, remaining string)
}
