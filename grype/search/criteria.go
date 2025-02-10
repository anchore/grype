package search

import (
	"fmt"
	"iter"
	"reflect"
	"slices"

	"github.com/anchore/grype/grype/vulnerability"
)

// ------- Utilities -------

// CriteriaIterator processes all conditions into distinct sets of flattened criteria
func CriteriaIterator(criteria []vulnerability.Criteria) iter.Seq2[int, []vulnerability.Criteria] {
	if len(criteria) == 0 {
		return func(_ func(int, []vulnerability.Criteria) bool) {}
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
	case and:
		// we replace this criteria object with its constituent parts
		return processRemaining(row, append(item, criteria...), yield)
	case or:
		for _, option := range item {
			if !processRemainingItem(row, criteria, option, yield) {
				return false
			}
		}
	default:
		return processRemaining(append(row, item), criteria, yield)
	}
	return true // continue
}

var allowedMultipleCriteria = []reflect.Type{reflect.TypeOf(funcCriteria{})}

// ValidateCriteria asserts that there are no incorrect duplications of criteria
// e.g. multiple ByPackageName() which would result in no matches, while Or(pkgName1, pkgName2) is allowed
func ValidateCriteria(criteria []vulnerability.Criteria) error {
	for _, row := range CriteriaIterator(criteria) { // process OR conditions into flattened lists of AND conditions
		seenTypes := make(map[reflect.Type]interface{})

		for _, criterion := range row {
			criterionType := reflect.TypeOf(criterion)

			if slices.Contains(allowedMultipleCriteria, criterionType) {
				continue
			}

			if previous, exists := seenTypes[criterionType]; exists {
				return fmt.Errorf("multiple conflicting criteria specified: %+v %+v", previous, criterion)
			}

			seenTypes[criterionType] = criterion
		}
	}
	return nil
}

// orCriteria provides a way to specify multiple criteria to be used, only requiring one to match
type or []vulnerability.Criteria

func Or(criteria ...vulnerability.Criteria) vulnerability.Criteria {
	return or(criteria)
}

func (c or) MatchesVulnerability(v vulnerability.Vulnerability) (bool, error) {
	for _, crit := range c {
		matches, err := crit.MatchesVulnerability(v)
		if matches || err != nil {
			return matches, err
		}
	}
	return false, nil
}

var _ interface {
	vulnerability.Criteria
} = (*or)(nil)

// andCriteria provides a way to specify multiple criteria to be used, all required
type and []vulnerability.Criteria

func And(criteria ...vulnerability.Criteria) vulnerability.Criteria {
	return and(criteria)
}

func (c and) MatchesVulnerability(v vulnerability.Vulnerability) (bool, error) {
	for _, crit := range c {
		matches, err := crit.MatchesVulnerability(v)
		if matches || err != nil {
			return matches, err
		}
	}
	return false, nil
}
