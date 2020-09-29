package version

import (
	"fmt"
	"strings"
)

type constraintExpression struct {
	units       [][]constraintUnit // only supports or'ing a group of and'ed groups
	comparators [][]Comparator     // only supports or'ing a group of and'ed groups
}

func newConstraintExpression(phrase string, genFn comparatorGenerator) (constraintExpression, error) {
	rootExpression := constraintExpression{
		units:       make([][]constraintUnit, 0),
		comparators: make([][]Comparator, 0),
	}

	if strings.Contains(phrase, "(") || strings.Contains(phrase, ")") {
		return constraintExpression{}, fmt.Errorf("version constraint expression groups are unsupported (use of parentheses)")
	}

	orParts := strings.Split(phrase, string(OR))
	for _, part := range orParts {
		units, err := splitConstraintPhrase(part)
		if err != nil {
			return constraintExpression{}, err
		}
		rootExpression.units = append(rootExpression.units, units)
		comparators := make([]Comparator, len(units))
		for idx, unit := range units {
			theComparator, err := genFn(unit)
			if err != nil {
				return constraintExpression{}, fmt.Errorf("failed to create comparator for '%s': %w", unit, err)
			}
			comparators[idx] = theComparator
		}
		rootExpression.comparators = append(rootExpression.comparators, comparators)
	}

	return rootExpression, nil
}

func (c *constraintExpression) satisfied(other *Version) (bool, error) {
	oneSatisfied := false
	for i, andOperand := range c.comparators {
		allSatisfied := true
		for j, andUnit := range andOperand {
			result, err := andUnit.Compare(other)
			if err != nil {
				return false, fmt.Errorf("uncomparable %+v %+v: %w", andUnit, other, err)
			}
			constraintUnit := c.units[i][j]

			if !constraintUnit.Satisfied(result) {
				allSatisfied = false
			}
		}

		oneSatisfied = oneSatisfied || allSatisfied
	}
	return oneSatisfied, nil
}
