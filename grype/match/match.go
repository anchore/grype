package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

var ErrCannotMerge = fmt.Errorf("unable to merge vulnerability matches")

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	Details       Details                     // all the ways this particular match was made.
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%q types=%q)", m.Package, m.Vulnerability.String(), m.Details.Types())
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		coreFingerprint: coreFingerprint{
			vulnerabilityID:        m.Vulnerability.ID,
			vulnerabilityNamespace: m.Vulnerability.Namespace,
			packageID:              m.Package.ID,
		},
		vulnerabilityFixes: strings.Join(m.Vulnerability.Fix.Versions, ","),
	}
}

func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	// there are cases related vulnerabilities are synthetic, for example when
	// orienting results by CVE. we need to keep track of these
	related := strset.New()
	for _, r := range m.Vulnerability.RelatedVulnerabilities {
		related.Add(referenceID(r))
	}
	for _, r := range other.Vulnerability.RelatedVulnerabilities {
		if related.Has(referenceID(r)) {
			continue
		}
		m.Vulnerability.RelatedVulnerabilities = append(m.Vulnerability.RelatedVulnerabilities, r)
	}

	// for stable output
	sort.Slice(m.Vulnerability.RelatedVulnerabilities, func(i, j int) bool {
		a := m.Vulnerability.RelatedVulnerabilities[i]
		b := m.Vulnerability.RelatedVulnerabilities[j]
		return strings.Compare(referenceID(a), referenceID(b)) < 0
	})

	// also keep details from the other match that are unique
	detailIDs := strset.New()
	for _, d := range m.Details {
		detailIDs.Add(d.ID())
	}
	for _, d := range other.Details {
		if detailIDs.Has(d.ID()) {
			continue
		}
		m.Details = append(m.Details, d)
	}

	// for stable output
	sort.Sort(m.Details)

	// retain all unique CPEs for consistent output
	m.Vulnerability.CPEs = cpe.Merge(m.Vulnerability.CPEs, other.Vulnerability.CPEs)
	if m.Vulnerability.CPEs == nil {
		// ensure we always have a non-nil slice
		m.Vulnerability.CPEs = []cpe.CPE{}
	}

	return nil
}

// referenceID returns an "ID" string for a vulnerability.Reference
func referenceID(r vulnerability.Reference) string {
	return fmt.Sprintf("%s:%s", r.Namespace, r.ID)
}
