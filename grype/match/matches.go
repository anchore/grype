package match

import (
	"github.com/anchore/grype/internal/log"
	"sort"

	"github.com/anchore/grype/grype/pkg"
)

type Matches struct {
	byFingerprint map[Fingerprint]Match
	byPackage     map[pkg.ID][]Fingerprint
}

func NewMatches() Matches {
	return Matches{
		byFingerprint: make(map[Fingerprint]Match),
		byPackage:     make(map[pkg.ID][]Fingerprint),
	}
}

// GetByPkgID returns a slice of potential matches from an ID
func (r *Matches) GetByPkgID(id pkg.ID) (matches []Match) {
	for _, fingerprint := range r.byPackage[id] {
		matches = append(matches, r.byFingerprint[fingerprint])
	}
	return matches
}

func (r *Matches) Merge(other Matches) {
	for pkgID, fingerprints := range other.byPackage {
		for _, fingerprint := range fingerprints {
			r.add(pkgID, other.byFingerprint[fingerprint])
		}
	}
}

func (r *Matches) add(id pkg.ID, matches ...Match) {
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
		} else {
			r.byFingerprint[fingerprint] = newMatch
		}

		// keep track of which matches correspond to which packages
		r.byPackage[id] = append(r.byPackage[id], fingerprint)
	}
}

func (r *Matches) Add(p pkg.Package, matches ...Match) {
	r.add(p.ID, matches...)
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
