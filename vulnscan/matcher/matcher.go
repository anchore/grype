package matcher

import (
	"github.com/anchore/imgbom/imgbom/distro"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher interface {
	Types() []pkg.Type
	Match(vulnerability.Provider, distro.Distro, *pkg.Package) ([]match.Match, error)
}
