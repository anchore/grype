package v6

import (
	"fmt"
	"sort"
	"strings"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/build/transformers"
)

// this file drops the package rows an `nvd` entry gets from CNA data (and from the curated CPE mappings) when
// another provider already has a row for the same package, so a CVE and a GHSA that alias it do not both report
// the same package. GHSA records are the usual other side: they name the same packages and carry reviewed ranges.
//
// the decision is made in Close, after every entry has been seen, so the result does not depend on the order in which
// providers are processed:
//   - observe records every non-nvd package handle as (CVE ID, package type, name), for each CVE ID the handle's
//     vulnerability names or aliases. It runs before the govulndb merge holds Go entries, and unwraps the govulndb
//     handle wrapper for the read only.
//   - hold keeps back every nvd entry that has package handles. The entry itself is held unchanged, so the govulndb
//     merge still sees the entries it sees today.
//   - reconcile removes the held entries' package handles that were observed, and records each drop on the
//     vulnerability's modifications. Vulnerability and CPE handles are always kept.

// nvdPackageKey identifies a package of a CVE. All fields are lowercase, matching how packages are compared at
// match time (collate nocase).
type nvdPackageKey struct {
	cve       string
	ecosystem string
	name      string
}

type nvdPackageMerger struct {
	// covered maps each observed package to the lowest ID of a non-nvd vulnerability that names it, so the
	// modification a drop records does not depend on arrival order.
	covered map[nvdPackageKey]string

	held []*transformers.RelatedEntries
}

func newNVDPackageMerger() *nvdPackageMerger {
	return &nvdPackageMerger{covered: make(map[nvdPackageKey]string)}
}

func isNVD(h *db.VulnerabilityHandle) bool {
	return strings.EqualFold(h.ProviderID, "nvd")
}

// observe records the packages of a non-nvd entry. The entry is not changed.
func (m *nvdPackageMerger) observe(entry transformers.RelatedEntries) {
	h := entry.VulnerabilityHandle
	// a withdrawn advisory never matches, so its rows cannot stand in for the CNA's (see goVulnDBMerger)
	if h == nil || isNVD(h) || h.Status == db.VulnerabilityRejected {
		return
	}

	for _, rel := range entry.Related {
		var aph db.AffectedPackageHandle
		switch r := rel.(type) {
		case db.AffectedPackageHandle:
			aph = r
		case transformers.GoVulnDBAffectedPackage:
			aph = r.Handle
		default:
			continue
		}
		if aph.Package == nil {
			continue
		}

		m.cover(h.Name, aph.Package, h.Name)
		if h.BlobValue != nil {
			for _, alias := range h.BlobValue.Aliases {
				m.cover(alias, aph.Package, h.Name)
			}
		}
		if aph.BlobValue != nil {
			for _, cve := range aph.BlobValue.CVEs {
				m.cover(cve, aph.Package, h.Name)
			}
		}
	}
}

func (m *nvdPackageMerger) cover(id string, pkg *db.Package, by string) {
	id = strings.ToLower(id)
	// only CVE entries are held, so no other ID can match
	if !strings.HasPrefix(id, "cve-") {
		return
	}
	key := nvdPackageKey{cve: id, ecosystem: strings.ToLower(pkg.Ecosystem), name: strings.ToLower(pkg.Name)}
	if current, ok := m.covered[key]; !ok || by < current {
		m.covered[key] = by
	}
}

// hold keeps back an nvd entry that has package handles until reconcile, returning true when it did.
func (m *nvdPackageMerger) hold(entry transformers.RelatedEntries) bool {
	if entry.VulnerabilityHandle == nil || !isNVD(entry.VulnerabilityHandle) {
		return false
	}
	for _, rel := range entry.Related {
		if _, ok := rel.(db.AffectedPackageHandle); ok {
			m.held = append(m.held, &entry)
			return true
		}
	}
	return false
}

// reconcile returns the held entries, in arrival order, without the package handles another provider covers. The
// merger's state is reset before returning.
func (m *nvdPackageMerger) reconcile() []transformers.RelatedEntries {
	out := make([]transformers.RelatedEntries, 0, len(m.held))
	for _, entry := range m.held {
		m.dropCovered(entry)
		out = append(out, *entry)
	}

	m.held = nil
	m.covered = make(map[nvdPackageKey]string)
	return out
}

func (m *nvdPackageMerger) dropCovered(entry *transformers.RelatedEntries) {
	handle := entry.VulnerabilityHandle
	cve := strings.ToLower(handle.Name)

	var kept []any
	changesBy := make(map[string][]string)
	for _, rel := range entry.Related {
		if aph, ok := rel.(db.AffectedPackageHandle); ok && aph.Package != nil {
			key := nvdPackageKey{cve: cve, ecosystem: strings.ToLower(aph.Package.Ecosystem), name: strings.ToLower(aph.Package.Name)}
			if by, covered := m.covered[key]; covered {
				changesBy[by] = append(changesBy[by], fmt.Sprintf("dropped %s:%s: covered by %s", aph.Package.Ecosystem, aph.Package.Name, by))
				continue
			}
		}
		kept = append(kept, rel)
	}

	if len(changesBy) == 0 {
		return
	}
	entry.Related = kept

	if handle.BlobValue == nil {
		return
	}
	byIDs := make([]string, 0, len(changesBy))
	for by := range changesBy {
		byIDs = append(byIDs, by)
	}
	sort.Strings(byIDs)
	for _, by := range byIDs {
		handle.BlobValue.Modifications = append(handle.BlobValue.Modifications, db.Modification{URL: by, Changes: changesBy[by]})
	}
}
