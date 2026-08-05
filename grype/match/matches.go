package match

import (
	"sort"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

type Matches struct {
	byFingerprint     map[Fingerprint]Match
	byCoreFingerprint map[coreFingerprint]map[Fingerprint]struct{}
	byPackage         map[pkg.ID]map[Fingerprint]struct{}
}

func NewMatches(matches ...Match) Matches {
	m := newMatches()
	m.Add(matches...)
	return m
}

func newMatches() Matches {
	return Matches{
		byFingerprint:     make(map[Fingerprint]Match),
		byCoreFingerprint: make(map[coreFingerprint]map[Fingerprint]struct{}),
		byPackage:         make(map[pkg.ID]map[Fingerprint]struct{}),
	}
}

// GetByPkgID returns a slice of potential matches from an ID
func (r *Matches) GetByPkgID(id pkg.ID) (matches []Match) {
	for fingerprint := range r.byPackage[id] {
		matches = append(matches, r.byFingerprint[fingerprint])
	}
	return matches
}

// AllByPkgID returns a map of all matches organized by package ID
func (r *Matches) AllByPkgID() map[pkg.ID][]Match {
	matches := make(map[pkg.ID][]Match)
	for id, fingerprints := range r.byPackage {
		for fingerprint := range fingerprints {
			matches[id] = append(matches[id], r.byFingerprint[fingerprint])
		}
	}
	return matches
}

func (r *Matches) Merge(other Matches) {
	for _, fingerprints := range other.byPackage {
		for fingerprint := range fingerprints {
			r.Add(other.byFingerprint[fingerprint])
		}
	}
}

func (r *Matches) Diff(other Matches) *Matches {
	diff := newMatches()
	for fingerprint := range r.byFingerprint {
		if _, exists := other.byFingerprint[fingerprint]; !exists {
			diff.Add(r.byFingerprint[fingerprint])
		}
	}
	return &diff
}

func (r *Matches) Add(matches ...Match) {
	for _, newMatch := range matches {
		newFp := newMatch.Fingerprint()

		// add or merge the new match with an existing match
		r.addOrMerge(newMatch, newFp)

		// track common elements (core fingerprint + package index)

		if _, exists := r.byCoreFingerprint[newFp.coreFingerprint]; !exists {
			r.byCoreFingerprint[newFp.coreFingerprint] = make(map[Fingerprint]struct{})
		}

		r.byCoreFingerprint[newFp.coreFingerprint][newFp] = struct{}{}

		if _, exists := r.byPackage[newMatch.Package.ID]; !exists {
			r.byPackage[newMatch.Package.ID] = make(map[Fingerprint]struct{})
		}
		r.byPackage[newMatch.Package.ID][newFp] = struct{}{}
	}
}

func (r *Matches) addOrMerge(newMatch Match, newFp Fingerprint) {
	// a) if there is an exact fingerprint match, then merge with that
	// b) otherwise, look for core fingerprint matches (looser rules)
	//   we prefer direct matches to indirect matches:
	//    1. if the new match is a direct match and there is an indirect match, replace the indirect match with the direct match
	//    2. if the new match is an indirect match and there is a direct match, merge with the existing direct match
	// c) this is a new match

	if existingMatch, exists := r.byFingerprint[newFp]; exists {
		// case A
		// Merge keeps the receiver's vulnerability metadata, and matches are not always added in a
		// deterministic order (Matches.Enumerate ranges over a map), so pick the survivor explicitly
		// rather than letting it fall out of arrival order.
		keep, absorb := existingMatch, newMatch
		if prefersVulnerabilityOf(newMatch, existingMatch) {
			keep, absorb = newMatch, existingMatch
		}

		if err := keep.Merge(absorb); err != nil {
			log.WithFields("original", keep.String(), "new", absorb.String(), "error", err).Warn("unable to merge matches")
			// at least capture the additional details
			keep.Details = append(keep.Details, absorb.Details...)
		}

		r.byFingerprint[newFp] = keep
	} else if existingFingerprints, exists := r.byCoreFingerprint[newFp.coreFingerprint]; exists {
		// case B
		if !r.mergeCoreMatches(newMatch, newFp, existingFingerprints) {
			// case C (we should not drop this match if we were unable to merge it)
			r.byFingerprint[newFp] = newMatch
		}
	} else {
		// case C
		r.byFingerprint[newFp] = newMatch
	}
}

func (r *Matches) mergeCoreMatches(newMatch Match, newFp Fingerprint, existingFingerprints map[Fingerprint]struct{}) bool {
	for existingFp := range existingFingerprints {
		existingMatch := r.byFingerprint[existingFp]

		shouldSupersede := hasMatchType(newMatch.Details, ExactDirectMatch) && hasExclusivelyAnyMatchTypes(existingMatch.Details, ExactIndirectMatch)
		if shouldSupersede {
			// case B1
			if replaced := r.replace(newMatch, existingFp, newFp, existingMatch.Details...); !replaced {
				log.WithFields("original", existingMatch.String(), "new", newMatch.String()).Trace("unable to replace match")
				// at least capture the new details
				existingMatch.Details = append(existingMatch.Details, newMatch.Details...)
			} else {
				return true
			}
		}

		// case B2
		if err := existingMatch.Merge(newMatch); err != nil {
			log.WithFields("original", existingMatch.String(), "new", newMatch.String(), "error", err).Trace("unable to merge matches")
			// at least capture the new details
			existingMatch.Details = append(existingMatch.Details, newMatch.Details...)
		} else {
			return true
		}
	}
	return false
}

func (r *Matches) replace(m Match, ogFp, newFp Fingerprint, extraDetails ...Detail) bool {
	if ogFp.coreFingerprint != newFp.coreFingerprint {
		return false
	}

	// update indexes
	for pkgID, fingerprints := range r.byPackage {
		if _, exists := fingerprints[ogFp]; exists {
			delete(fingerprints, ogFp)
			fingerprints[newFp] = struct{}{}
			r.byPackage[pkgID] = fingerprints
		}
	}

	// update the match
	delete(r.byFingerprint, ogFp)
	m.Details = append(m.Details, extraDetails...)
	sort.Sort(m.Details)
	r.byFingerprint[newFp] = m
	return true
}

func (r *Matches) Enumerate() <-chan Match {
	channel := make(chan Match)
	go func() {
		defer close(channel)
		for _, match := range r.byFingerprint {
			channel <- match
		}
	}()
	return channel
}

func (r *Matches) Sorted() []Match {
	matches := make([]Match, 0)
	for m := range r.Enumerate() {
		matches = append(matches, m)
	}

	sort.Sort(ByElements(matches))

	return matches
}

// Count returns the total number of matches in a result
func (r *Matches) Count() int {
	return len(r.byFingerprint)
}

// prefersVulnerabilityOf reports whether candidate's vulnerability metadata should survive a merge
// with incumbent, given that the two share a fingerprint.
//
// Sharing a fingerprint does not mean the two matches describe the same upstream record. Normalizing
// by CVE rewrites an ecosystem record's ID and namespace to the CVE it aliases, which makes it collide
// with the NVD record for that CVE and package. Only the identity is rewritten: the description, data
// source, severity and fix data still describe the record the match was originally found in, so which
// of the two survives is visible in the output.
//
// Prefer the record found by matching the package directly against an ecosystem advisory. Those records
// carry curated fix data, while a record reached only by CPE describes the same CVE more loosely.
func prefersVulnerabilityOf(candidate, incumbent Match) bool {
	candidateRank, incumbentRank := vulnerabilityRank(candidate), vulnerabilityRank(incumbent)
	if candidateRank != incumbentRank {
		return candidateRank > incumbentRank
	}

	// equally ranked records still need a stable winner, otherwise the result depends on which of the
	// two happened to be added first. A record whose metadata could not be resolved has no
	// description or data source to contribute, so it loses to one that can be identified.
	candidateSource, incumbentSource := vulnerabilitySource(candidate), vulnerabilitySource(incumbent)
	if candidateSource == "" || incumbentSource == "" {
		return incumbentSource == "" && candidateSource != ""
	}

	return candidateSource < incumbentSource
}

// vulnerabilityRank orders matches by how directly the vulnerability record was tied to the package.
func vulnerabilityRank(m Match) int {
	switch {
	case hasMatchType(m.Details, ExactDirectMatch):
		return 2
	case hasMatchType(m.Details, ExactIndirectMatch):
		return 1
	}
	return 0
}

// vulnerabilitySource identifies the record a match's vulnerability metadata came from. Two matches
// that share a fingerprint can still originate from different providers.
func vulnerabilitySource(m Match) string {
	if m.Vulnerability.Metadata == nil {
		return ""
	}
	return m.Vulnerability.Metadata.Namespace + "|" + m.Vulnerability.Metadata.DataSource
}

func hasMatchType(details Details, ty Type) bool {
	for _, d := range details {
		if d.Type == ty {
			return true
		}
	}
	return false
}

func hasExclusivelyAnyMatchTypes(details Details, tys ...Type) bool {
	allowed := strset.New()
	for _, ty := range tys {
		allowed.Add(string(ty))
	}
	var found bool
	for _, d := range details {
		if allowed.Has(string(d.Type)) {
			found = true
		} else {
			return false
		}
	}
	return found
}
