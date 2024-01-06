package processor

import (
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/store"
)

var _ match.Processor = (*matchExclusionFilter)(nil)

type matchExclusionFilter struct {
	store store.Store
}

func NewMatchExclusionFilter(s store.Store) match.Processor {
	return idNormalizer{
		store: s,
	}
}

func (k matchExclusionFilter) ProcessMatches(context pkg.Context, matches match.Matches, ignoredMatches []match.IgnoredMatch) (match.Matches, []match.IgnoredMatch, error) {
	// Filter out matches based on records in the database exclusion table and hard-coded rules
	filtered, dropped := match.ApplyExplicitIgnoreRules(k.store, match.NewMatches(matches...))

	additionalMatches := filtered.Sorted()
	//logPackageMatches(p, additionalMatches)
	//logExplicitDroppedPackageMatches(p, dropped)

	return matches, ignoredMatches, nil
}
