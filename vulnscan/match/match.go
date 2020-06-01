package match

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Match struct {
	Confidence    float64
	Vulnerability vulnerability.Vulnerability
	Package       *pkg.Package
	// SearchKey provides an indication of how this match was found.
	// TODO: enhance this to be a rich object
	SearchKey string
}

func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%s key='%s' confidence=%f)", m.Package.String(), m.Vulnerability.String(), m.SearchKey, m.Confidence)
}
