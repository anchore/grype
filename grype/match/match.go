package match

import (
	"fmt"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
)

type Match struct {
	Type          Type
	Confidence    float64
	Vulnerability vulnerability.Vulnerability
	Package       *pkg.Package
	// SearchKey provides an indication of how this match was found.
	// TODO: is this a good name for what it represents? (which is an audit trail of HOW we got this match from the store)
	SearchKey       map[string]interface{}
	SearchMatches   map[string]interface{}
	IndirectPackage *pkg.Package
	Matcher         MatcherType
}

func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%s type='%s' foundBy='%s')", m.Package, m.Vulnerability.String(), m.Type, m.Matcher)
}

func (m Match) Summary() string {
	return fmt.Sprintf("vuln='%s' type='%s' key='%s' foundBy='%s'", m.Vulnerability.ID, m.Type, m.SearchKey, m.Matcher)
}
