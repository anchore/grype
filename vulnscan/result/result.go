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
	// TODO: should we dedup matches? or assume that dups are ok?
	for pkgID, matches := range other.byPackage {
		r.add(pkgID, matches...)
	}
}

func (r *Result) add(id pkg.ID, matches ...match.Match) {
	// TODO: should we not create new entries when no matches are given?
	if _, ok := r.byPackage[id]; !ok {
		r.byPackage[id] = make([]match.Match, 0)
	}
	r.byPackage[id] = append(r.byPackage[id], matches...)
}

func (r *Result) Add(p pkg.Package, matches ...match.Match) {
	// TODO: should we not create new entries when no matches are given?
	r.add(p.ID(), matches...)
}
