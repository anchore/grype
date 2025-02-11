package match

import (
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Matcher is the interface to implement to provide top-level package-to-match
type Matcher interface {
	PackageTypes() []syftPkg.Type

	Type() MatcherType

	// Match is called for every package found, returning any matches and an optional Ignorer which will be applied
	// after all matches are found
	Match(vp vulnerability.Provider, p pkg.Package) ([]Match, []IgnoredMatch, error)
}
