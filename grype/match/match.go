package match

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Type          Type                        // The kind of match made (an exact match, fuzzy match, indirect vs direct, etc).
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	MatchDetails  []Details                   // all ways in which how this particular match was made.
}

type Details struct {
	SearchedBy interface{} // The specific attributes that were used to search (other than package name and version) --this indicates "how" the match was made.
	MatchedOn  interface{} // The specific attributes on the vulnerability object that were matched with --this indicates "what" was matched on / within.
	Matcher    MatcherType // The matcher object that discovered the match.
	Confidence float64     // The certainty of the match as a ratio (currently unused, reserved for future use).
}

type Fingerprint struct {
	VulnerabilityID        string
	VulnerabilityNamespace string
	VulnerabilityFixes     string
	PackageID              pkg.ID // this encodes package name, version, type, location
	MatchType              Type
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%q type=%q)", m.Package, m.Vulnerability.String(), m.Type)
}

func (m Match) Summary() string {
	return fmt.Sprintf("vuln=%q type=%q searchedBy=%q foundBy=%q", m.Vulnerability.ID, m.Type, m.MatchDetails[0].SearchedBy, m.MatchDetails[0].Matcher)
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		VulnerabilityID:        m.Vulnerability.ID,
		VulnerabilityNamespace: m.Vulnerability.Namespace,
		VulnerabilityFixes:     strings.Join(m.Vulnerability.Fix.Versions, ","),
		PackageID:              m.Package.ID,
		MatchType:              m.Type,
	}
}
