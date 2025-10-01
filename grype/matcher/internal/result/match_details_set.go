package result

import "github.com/anchore/grype/grype/match"

type MatchDetailsSet struct {
	order []match.Detail
	seen  map[match.Detail]struct{}
}

func NewMatchDetailsSet(ds ...match.Detail) MatchDetailsSet {
	s := MatchDetailsSet{
		order: []match.Detail{},
		seen:  make(map[match.Detail]struct{}),
	}
	for _, detail := range ds {
		s.Add(detail)
	}
	return s
}

func (ds *MatchDetailsSet) Add(detail match.Detail) {
	if _, exists := ds.seen[detail]; !exists {
		ds.order = append(ds.order, detail)
		ds.seen[detail] = struct{}{}
	}
}

func (ds MatchDetailsSet) ToSlice() []match.Detail {
	return ds.order
}
