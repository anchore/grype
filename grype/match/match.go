package match

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
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
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		packageID:              m.Package.ID,
	}
}

// Merge folds another match for the same finding -- the same vulnerability, from the same source, on
// the same package -- into this one.
//
// Several records can describe one finding and disagree about the particulars: an NVD CVE listing
// two vulnerable CPEs that the package matches, or an advisory found both directly and through the
// package's upstream. Each is a separate record with its own constraint and fixed-in version, but to
// a user they are one finding, so they are reported as one match.
//
// The record that produced the strongest match supplies the fields that cannot be combined --
// severity metadata, package name, fix state -- and the remainder are unioned: fixed-in versions,
// constraints, advisories, aliases, CPEs and match details. Every record contributes its own detail,
// so how each one matched is preserved even though only one describes the finding as a whole.
func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	// the strongest match describes the finding; the weaker record only contributes to the unions
	// below. when neither is stronger the receiver wins, so callers must add matches in a
	// deterministic order (this is why normalization iterates Sorted() and not Enumerate()).
	base, secondary := m.Vulnerability, other.Vulnerability
	if other.Details.rank() < m.Details.rank() {
		base, secondary = other.Vulnerability, m.Vulnerability
	}

	base.Fix = mergeFix(base.Fix, secondary.Fix)

	// note: the combined constraint is informational -- whether each record applies was decided
	// before the match was created, and every record's own constraint is preserved on the detail it
	// contributed.
	base.Constraint = version.CombineConstraints(base.Constraint, secondary.Constraint)

	// there are cases related vulnerabilities are synthetic, for example when
	// orienting results by CVE. we need to keep track of these
	base.RelatedVulnerabilities = mergeReferences(base.RelatedVulnerabilities, secondary.RelatedVulnerabilities)
	base.Advisories = mergeAdvisories(base.Advisories, secondary.Advisories)

	// retain all unique CPEs for consistent output
	base.CPEs = cpe.Merge(base.CPEs, secondary.CPEs)
	if base.CPEs == nil {
		// ensure we always have a non-nil slice
		base.CPEs = []cpe.CPE{}
	}

	m.Vulnerability = base
	m.Details = mergeDetails(m.Details, other.Details)

	return nil
}

// mergeFix unions the fix information of two records describing the same finding. A fix known to one
// record is a fix for the finding, so a "fixed" state wins over a record that reports none -- an NVD
// record that lists a vulnerable CPE without a version end carries no fix at all, and must not mask
// the fixed-in version a sibling record reports for the same CVE.
func mergeFix(base, other vulnerability.Fix) vulnerability.Fix {
	out := vulnerability.Fix{
		State: base.State,
	}

	if versions := slices.Concat(base.Versions, other.Versions); len(versions) > 0 {
		slices.Sort(versions)
		out.Versions = slices.Compact(versions)
	}

	seen := make(map[vulnerability.FixAvailable]struct{}, len(base.Available)+len(other.Available))
	for _, a := range slices.Concat(base.Available, other.Available) {
		if _, exists := seen[a]; exists {
			continue
		}
		seen[a] = struct{}{}
		out.Available = append(out.Available, a)
	}

	switch {
	case other.State == vulnerability.FixStateFixed:
		out.State = vulnerability.FixStateFixed
	case out.State == "" || out.State == vulnerability.FixStateUnknown:
		if other.State != "" {
			out.State = other.State
		}
	}

	return out
}

// mergeReferences unions two sets of vulnerability references (aliases), sorted for stable output.
func mergeReferences(base, other []vulnerability.Reference) []vulnerability.Reference {
	seen := make(map[vulnerability.Reference]struct{}, len(base)+len(other))
	var out []vulnerability.Reference
	for _, r := range slices.Concat(base, other) {
		// comparable without Internal reference
		key := vulnerability.Reference{ID: r.ID, Namespace: r.Namespace}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}

	// for stable output
	slices.SortFunc(out, func(a, b vulnerability.Reference) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// mergeAdvisories unions two sets of advisories, sorted for stable output.
func mergeAdvisories(base, other []vulnerability.Advisory) []vulnerability.Advisory {
	// vulnerability.Advisory is comparable, so it keys the set on its own
	seen := make(map[vulnerability.Advisory]struct{}, len(base)+len(other))
	var out []vulnerability.Advisory
	for _, a := range slices.Concat(base, other) {
		if _, exists := seen[a]; exists {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	// for stable output
	slices.SortFunc(out, func(a, b vulnerability.Advisory) int {
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.Link, b.Link)
	})
	return out
}
