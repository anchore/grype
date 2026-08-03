package result

import "github.com/anchore/grype/grype/match"

type MatchDetailsSet struct {
	order []match.Detail
	// keyed by Detail.ID() (a hashstructure hash) rather than the Detail value itself: Found/SearchedBy
	// are `any` and may hold slice-bearing types (e.g. EcosystemResult.MatchedSymbols, CPEResult.CPEs)
	// that are not valid Go map keys and would panic on direct keying.
	seen map[string]struct{}
}

func NewMatchDetailsSet(ds ...match.Detail) MatchDetailsSet {
	s := MatchDetailsSet{
		order: []match.Detail{},
		seen:  make(map[string]struct{}),
	}
	for _, detail := range ds {
		s.Add(detail)
	}
	return s
}

func (ds *MatchDetailsSet) Add(detail match.Detail) {
	id := detail.ID()
	if _, exists := ds.seen[id]; !exists {
		ds.order = append(ds.order, detail)
		ds.seen[id] = struct{}{}
	}
}

func (ds MatchDetailsSet) ToSlice() []match.Detail {
	return ds.order
}
