package match

import (
	"fmt"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/vulnerability"
)

type Match struct {
	Type          Type
	Confidence    float64
	Vulnerability vulnerability.Vulnerability
	Package       *pkg.Package
	// SearchKey provides an indication of how this match was found.
	// TODO: is this a good name for what it represents? (which is an audit trail of HOW we got this match from the store)
	SearchKey       string
	IndirectPackage *pkg.Package
	Matcher         string
}

func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%s confidence=%f type='%s' key='%s' foundBy='%s')", m.Package, m.Vulnerability.String(), m.Confidence, m.Type, m.SearchKey, m.Matcher)
}

func (m Match) Summary() string {
	return fmt.Sprintf("vuln='%s' confidence=%0.2f type='%s' key='%s' foundBy='%s')", m.Vulnerability.ID, m.Confidence, m.Type, m.SearchKey, m.Matcher)
}
