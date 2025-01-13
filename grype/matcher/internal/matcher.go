package internal

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type TypedMatcher interface {
	PackageTypes() []syftPkg.Type
	Type() match.MatcherType
	Match(vulnerability.Provider, pkg.Package) ([]match.Match, []match.IgnoredMatch, error)
}
