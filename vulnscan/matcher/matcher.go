package matcher

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
)

type Matcher interface {
	Type() pkg.Type
	Match(match.Store, pkg.Package) []match.Match
}
