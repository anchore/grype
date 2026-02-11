package nvd

import (
	"sort"

	"github.com/anchore/grype/grype/db/internal/provider/unmarshal/nvd"
)

type uniquePkgTracker map[pkgCandidate][]nvd.CpeMatch

func newUniquePkgTracker() uniquePkgTracker {
	return make(uniquePkgTracker)
}

func (s uniquePkgTracker) Diff(other uniquePkgTracker) (missing []pkgCandidate, extra []pkgCandidate) {
	for k := range s {
		if !other.Contains(k) {
			missing = append(missing, k)
		}
	}

	for k := range other {
		if !s.Contains(k) {
			extra = append(extra, k)
		}
	}

	return
}

func (s uniquePkgTracker) Matches(i pkgCandidate) []nvd.CpeMatch {
	return s[i]
}

func (s uniquePkgTracker) Add(i pkgCandidate, match nvd.CpeMatch) {
	if _, ok := s[i]; !ok {
		s[i] = make([]nvd.CpeMatch, 0)
	}
	s[i] = append(s[i], match)
}

func (s uniquePkgTracker) Remove(i pkgCandidate) {
	delete(s, i)
}

func (s uniquePkgTracker) Contains(i pkgCandidate) bool {
	_, ok := s[i]
	return ok
}

func (s uniquePkgTracker) All() []pkgCandidate {
	res := make([]pkgCandidate, len(s))
	idx := 0
	for k := range s {
		res[idx] = k
		idx++
	}

	sort.SliceStable(res, func(i, j int) bool {
		return res[i].String() < res[j].String()
	})

	return res
}
