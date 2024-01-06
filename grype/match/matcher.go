package match

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

type Matcher interface {
	PackageTypes() []syftPkg.Type
	Type() MatcherType
	Match(vulnerability.Provider, *distro.Distro, pkg.Package) ([]Match, error)
}
