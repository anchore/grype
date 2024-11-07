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
		if err := existingMatch.Merge(newMatch); err != nil {
			log.WithFields("original", existingMatch.String(), "new", newMatch.String(), "error", err).Warn("unable to merge matches")
			// TODO: dropped match in this case, we should figure a way to handle this
		}

		r.byFingerprint[newFp] = existingMatch
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
			} else {
				return true
			}
		}

		// case B2
		if err := existingMatch.Merge(newMatch); err != nil {
			log.WithFields("original", existingMatch.String(), "new", newMatch.String(), "error", err).Warn("unable to merge matches")
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
