package match

import (
	"github.com/scylladb/go-set/strset"
	"sort"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

type Matches struct {
	byFingerprint map[Fingerprint]Match
	byPackage     map[pkg.ID]FingerprintSet
}

func NewMatches(matches ...Match) Matches {
	m := newMatches()
	m.Add(matches...)
	return m
}

func newMatches() Matches {
	return Matches{
		byFingerprint: make(map[Fingerprint]Match),
		byPackage:     make(map[pkg.ID]FingerprintSet),
	}
}

func (r Matches) PkgIDs() (ids []pkg.ID) {
	set := strset.New()
	for id := range r.byPackage {
		set.Add(string(id))
	}

	sort.Strings(set.List())

	for _, id := range set.List() {
		ids = append(ids, pkg.ID(id))
	}

	return ids
}

// GetByPkgID returns a slice of potential matches from an ID
func (r Matches) GetByPkgID(id pkg.ID) (matches []Match) {
	for _, fingerprint := range r.byPackage[id].ToSlice() {

		matches = append(matches, r.byFingerprint[fingerprint])
	}
	return matches
}

// AllByPkgID returns a map of all matches organized by package ID
func (r Matches) AllByPkgID() map[pkg.ID][]Match {
	matches := make(map[pkg.ID][]Match)
	for id, fingerprints := range r.byPackage {
		for _, fingerprint := range fingerprints.ToSlice() {
			matches[id] = append(matches[id], r.byFingerprint[fingerprint])
		}
	}
	return matches
}

func (r *Matches) Merge(other Matches) {
	r.Add(other.Sorted()...)
}

func (r Matches) Clone() Matches {
	// note: this does not handle deep copying of the Match object. If the caller desires this, they must do it themselves.
	return NewMatches(r.Sorted()...)
}

func (r Matches) Diff(other Matches) *Matches {
	diff := newMatches()
	for fingerprint := range r.byFingerprint {
		if _, exists := other.byFingerprint[fingerprint]; !exists {
			diff.Add(r.byFingerprint[fingerprint])
		}
	}
	return &diff
}

func (r *Matches) Add(matches ...Match) {
	if len(matches) == 0 {
		return
	}
	for _, newMatch := range matches {
		fingerprint := newMatch.Fingerprint()

		// add or merge the new match with an existing match
		if existingMatch, exists := r.byFingerprint[fingerprint]; exists {
			if err := existingMatch.Merge(newMatch); err != nil {
				log.Warnf("unable to merge matches: original=%q new=%q : %w", existingMatch.String(), newMatch.String(), err)
				// TODO: dropped match in this case, we should figure a way to handle this
			}
			r.byFingerprint[fingerprint] = existingMatch
		} else {
			r.byFingerprint[fingerprint] = newMatch
		}

		// keep track of which matches correspond to which packages
		if _, exists := r.byPackage[newMatch.Package.ID]; !exists {
			r.byPackage[newMatch.Package.ID] = NewFingerprintSet()
		}
		r.byPackage[newMatch.Package.ID].Add(fingerprint)
	}
}

func (r *Matches) Remove(matches ...Match) {
	for _, match := range matches {
		r.RemoveByFingerprint(match.Fingerprint())
	}
}

func (r *Matches) RemoveByFingerprint(fingerprints ...Fingerprint) {
	for _, fingerprint := range fingerprints {
		match, exists := r.byFingerprint[fingerprint]
		if !exists {
			return
		}

		delete(r.byFingerprint, fingerprint)

		if _, exists := r.byPackage[match.Package.ID]; exists {
			r.byPackage[match.Package.ID].Remove(fingerprint)
		}
	}
}

func (r Matches) Contains(match Match) bool {
	_, exists := r.byFingerprint[match.Fingerprint()]
	return exists
}

func (r Matches) Enumerate() <-chan Match {
	channel := make(chan Match)
	go func() {
		defer close(channel)
		for _, match := range r.byFingerprint {
			channel <- match
		}
	}()
	return channel
}

func (r Matches) Sorted() []Match {
	matches := make([]Match, 0)
	for m := range r.Enumerate() {
		matches = append(matches, m)
	}

	sort.Sort(ByElements(matches))

	return matches
}

// Count returns the total number of matches in a result
func (r Matches) Count() int {
	return len(r.byFingerprint)
}
