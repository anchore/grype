package matcher

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []pkg.Type
	Type() match.MatcherType
	Match(vulnerability.Provider, *distro.Distro, *pkg.Package) ([]match.Match, error)
}
