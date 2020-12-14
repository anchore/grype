package match

import (
	"fmt"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Type          Type                        // The kind of match made (an exact match, fuzzy match, indirect vs direct, etc).
	Confidence    float64                     // The certainty of the match as a ratio (currently unused, reserved for future use).
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	SearchKey     map[string]interface{}      // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	SearchMatches map[string]interface{}      // The specific attributes on the vulnerability object that were matched with --this indicates "what" was found in the match.
	Matcher       MatcherType                 // The matcher object that discovered the match.
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%s type='%s' foundBy='%s')", m.Package, m.Vulnerability.String(), m.Type, m.Matcher)
}

// Summary is a short string representation of the match object.
func (m Match) Summary() string {
	return fmt.Sprintf("vuln='%s' type='%s' key='%s' foundBy='%s'", m.Vulnerability.ID, m.Type, m.SearchKey, m.Matcher)
}
