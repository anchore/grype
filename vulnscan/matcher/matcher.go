package matcher

import (
	"github.com/anchore/imgbom/imgbom/os"
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Matcher interface {
	Types() []pkg.Type
	Match(vulnerability.Provider, os.OS, *pkg.Package) ([]match.Match, error)
}
