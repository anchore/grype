package match

import (
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

var ErrCannotMerge = fmt.Errorf("unable to merge vulnerability matches")

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	Details       Details                     // all ways in which how this particular match was made.
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%q types=%q)", m.Package, m.Vulnerability.String(), m.Details.Types())
}

func (m Match) Summary() string {
	return fmt.Sprintf("vuln=%q matchers=%s", m.Vulnerability.ID, m.Details.Matchers())
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		vulnerabilityFixes:     strings.Join(m.Vulnerability.Fix.Versions, ","),
		packageID:              m.Package.ID,
	}
}

func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	detailIDs := strset.New()
	for _, d := range m.Details {
		detailIDs.Add(d.ID())
	}

	// keep details from the other match that are unique
	for _, d := range other.Details {
		if detailIDs.Has(d.ID()) {
			continue
		}
		m.Details = append(m.Details, d)
	}
	return nil
}
