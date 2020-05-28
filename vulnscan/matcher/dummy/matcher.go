package dummy

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan-db/pkg/vulnerability"
	"github.com/anchore/vulnscan/vulnscan/match"
)

// TODO: delete me...

type Matcher struct {
}

func (m *Matcher) Type() pkg.Type {
	return pkg.DebPkg
}

func (m *Matcher) Match(match.Store, pkg.Package) []match.Match {
	return []match.Match{
		{
			Confidence:    42,
			Vulnerability: vulnerability.Vulnerability{},
			Package:       pkg.Package{},
			SearchKey:     "the key",
		},
	}
}
