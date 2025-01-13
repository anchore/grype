package search

import (
	"iter"

	"github.com/anchore/grype/grype/vulnerability"
)

// requiredCriteriaContainer is an interface criteria implementations may provide to give access
// to nested criteria, which may be expanded while processing unique criteria sets. for example,
// the "AND" condition implements this to allow FindVulnerabilities to determine nested database constraints
// that may be applied
type requiredCriteriaContainer interface {
	RequiredCriteria() []vulnerability.Criteria
}

// optionalCriteriaContainer is an interface criteria implementations may provide to give access
// to nested criteria, which may be expanded while processing unique criteria sets. for example,
// the "OR" condition implements this to allow FindVulnerabilities to determine nested database constraints
// that may be applied
type optionalCriteriaContainer interface {
	OptionalCriteria() []vulnerability.Criteria
}

// ------- Utilities -------

// byMany returns criteria which will search based on the provided single criteria function and multiple values
func byMany[T any](criteriaFn func(T) vulnerability.Criteria, c ...T) vulnerability.Criteria {
	return &orCriteria{
		criteria: reduce(c, nil, func(criteria []vulnerability.Criteria, t T) []vulnerability.Criteria {
			return append(criteria, criteriaFn(t))
		}),
	}
}

// CriteriaIterator processes all conditions into distinct sets of flattened criteria
func CriteriaIterator(criteria []vulnerability.Criteria) iter.Seq2[int, []vulnerability.Criteria] {
	if len(criteria) == 0 {
		return func(_ func(int, []vulnerability.Criteria) bool) {
		}
	}
	return func(yield func(int, []vulnerability.Criteria) bool) {
		idx := 0
		fn := func(criteria []vulnerability.Criteria) bool {
			out := yield(idx, criteria)
			idx++
			return out
		}
		_ = processRemaining(nil, criteria, fn)
	}
}

func processRemaining(row, criteria []vulnerability.Criteria, yield func([]vulnerability.Criteria) bool) bool {
	if len(criteria) == 0 {
		return yield(row)
	}
	return processRemainingItem(row, criteria[1:], criteria[0], yield)
}

func processRemainingItem(row, criteria []vulnerability.Criteria, item vulnerability.Criteria, yield func([]vulnerability.Criteria) bool) bool {
	switch item := item.(type) {
	case requiredCriteriaContainer:
		// we replace this criteria object with its constituent parts
		return processRemaining(row, append(item.RequiredCriteria(), criteria...), yield)
	case optionalCriteriaContainer:
		for _, option := range item.OptionalCriteria() {
			if !processRemainingItem(row, criteria, option, yield) {
				return false
			}
		}
	default:
		return processRemaining(append(row, item), criteria, yield)
	}
	return true // continue
}

// reduce is a simplistic reducer function
func reduce[Incoming any, Return any](values []Incoming, initial Return, reducer func(Return, Incoming) Return) Return {
	for _, value := range values {
		initial = reducer(initial, value)
	}
	return initial
}
