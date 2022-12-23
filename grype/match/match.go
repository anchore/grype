package match

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
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

	// similarly we need to retain unique CPEs for consistent output
	cpes := strset.New()
	for _, c := range m.Vulnerability.CPEs {
		cpes.Add(syftPkg.CPEString(c))
	}
	for _, c := range other.Vulnerability.CPEs {
		if cpes.Has(syftPkg.CPEString(c)) {
			continue
		}
		m.Vulnerability.CPEs = append(m.Vulnerability.CPEs, c)
	}

	// for stable output
	sort.Slice(m.Vulnerability.CPEs, func(i, j int) bool {
		a := m.Vulnerability.CPEs[i]
		b := m.Vulnerability.CPEs[j]
		return strings.Compare(syftPkg.CPEString(a), syftPkg.CPEString(b)) < 0
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
	sort.Slice(m.Details, func(i, j int) bool {
		a := m.Details[i]
		b := m.Details[j]
		return strings.Compare(a.ID(), b.ID()) < 0
	})

	return nil
}

// referenceID returns an "ID" string for a vulnerability.Reference
func referenceID(r vulnerability.Reference) string {
	return fmt.Sprintf("%s:%s", r.Namespace, r.ID)
}
