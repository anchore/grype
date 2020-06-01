package result

import (
	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/vulnscan/vulnscan/match"
)

type Result struct {
	byPackage map[pkg.ID][]match.Match
}

func NewResult() Result {
	return Result{
		byPackage: make(map[pkg.ID][]match.Match),
	}
}

func (r *Result) Merge(other Result) {
	// note: de-duplication of matches is an upstream concern (not here)
	for pkgID, matches := range other.byPackage {
		r.add(pkgID, matches...)
	}
}

func (r *Result) add(id pkg.ID, matches ...match.Match) {
	if len(matches) == 0 {
		// only packages with matches should be added
		return
	}
	if _, ok := r.byPackage[id]; !ok {
		r.byPackage[id] = make([]match.Match, 0)
	}
	r.byPackage[id] = append(r.byPackage[id], matches...)
}

func (r *Result) Add(p *pkg.Package, matches ...match.Match) {
	r.add(p.ID(), matches...)
}

func (r *Result) Enumerate() <-chan match.Match {
	channel := make(chan match.Match)
	go func() {
		defer close(channel)
		for _, matches := range r.byPackage {
			for _, match := range matches {
				channel <- match
			}
		}
	}()
	return channel
}
