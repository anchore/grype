package match

import (
	"github.com/anchore/grype/grype/pkg"
)

type Matches struct {
	byPackage map[pkg.ID][]Match
}

func NewMatches() Matches {
	return Matches{
		byPackage: make(map[pkg.ID][]Match),
	}
}

// GetByPkgID returns a slice of potential matches from an ID
func (r *Matches) GetByPkgID(id pkg.ID) []Match {
	matches, ok := r.byPackage[id]
	if !ok {
		return nil
	}
	return matches
}

func (r *Matches) Merge(other Matches) {
	// note: de-duplication of matches is an upstream concern (not here)
	for pkgID, matches := range other.byPackage {
		r.add(pkgID, matches...)
	}
}

func (r *Matches) add(id pkg.ID, matches ...Match) {
	if len(matches) == 0 {
		// only packages with matches should be added
		return
	}
	if _, ok := r.byPackage[id]; !ok {
		r.byPackage[id] = make([]Match, 0)
	}
	r.byPackage[id] = append(r.byPackage[id], matches...)
}

func (r *Matches) Add(p pkg.Package, matches ...Match) {
	r.add(p.ID(), matches...)
}

func (r *Matches) Enumerate() <-chan Match {
	channel := make(chan Match)
	go func() {
		defer close(channel)
		for _, matches := range r.byPackage {
			for _, m := range matches {
				channel <- m
			}
		}
	}()
	return channel
}

// Count returns the total number of matches in a result
func (r *Matches) Count() int {
	return len(r.byPackage)
}
