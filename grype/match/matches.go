package match

import (
	"sort"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/internal/log"
)

type Matches struct {
	byFingerprint map[Fingerprint]Match
	byPackage     map[pkg.ID]map[Fingerprint]struct{}
}

func NewMatches(matches ...Match) Matches {
	m := newMatches()
	m.Add(matches...)
	return m
}

func newMatches() Matches {
	return Matches{
		byFingerprint: make(map[Fingerprint]Match),
		byPackage:     make(map[pkg.ID]map[Fingerprint]struct{}),
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

// Add stores the given matches, folding each into any match already present for the same finding.
// A fingerprint is one vulnerability, from one source, on one package -- so records that describe
// that finding differently, such as two vulnerable CPEs of one CVE that the package matches, or an
// advisory found both directly and via the package's upstream, become a single match carrying all
// of their details rather than duplicate findings. See Match.Merge for how they are reconciled.
func (r *Matches) Add(matches ...Match) {
	for _, newMatch := range matches {
		fingerprint := newMatch.Fingerprint()

		if existingMatch, exists := r.byFingerprint[fingerprint]; exists {
			if err := existingMatch.Merge(newMatch); err != nil {
				// unreachable: an equal fingerprint is the only thing Merge rejects on
				log.WithFields("original", existingMatch.String(), "new", newMatch.String(), "error", err).Warn("unable to merge matches")
				// at least capture the additional details
				existingMatch.Details = mergeDetails(existingMatch.Details, newMatch.Details)
			}
			r.byFingerprint[fingerprint] = existingMatch
		} else {
			// dedup on the way in too, so a match stored without ever being merged is held to the
			// same standard as one that was
			newMatch.Details = mergeDetails(newMatch.Details)
			r.byFingerprint[fingerprint] = newMatch
		}

		if _, exists := r.byPackage[newMatch.Package.ID]; !exists {
			r.byPackage[newMatch.Package.ID] = make(map[Fingerprint]struct{})
		}
		r.byPackage[newMatch.Package.ID][fingerprint] = struct{}{}
	}
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
