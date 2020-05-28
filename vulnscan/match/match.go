package match

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan-db/pkg/vulnerability"
)

type Match struct {
	Confidence    float64
	Vulnerability vulnerability.Vulnerability
	Package       pkg.Package // is this needed? Or should we just capture the package ID (which is not stable between runs)?
	SearchKey     string      // what made this a hit? CPE, package-name-version, etc... we need to capture how this was matched (TODO)
}

// TODO: delete me... this will be done in vulnscan-db
type Store interface {
}
