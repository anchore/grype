package version

import (
	"errors"
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"
)

func CombineConstraints(constraints ...Constraint) Constraint {
	constraints = uniqueConstraints(constraints...)

	if len(constraints) == 0 {
		return nil
	}
	if len(constraints) == 1 {
		return constraints[0]
	}

	return combinedConstraint{
		OrOperands: constraints,
	}
}

type combinedConstraint struct {
	OrOperands []Constraint
}

func (c combinedConstraint) String() string {
	return fmt.Sprintf("%s (%s)", c.Value(), strings.ToLower(c.Format().String()))
}

func (c combinedConstraint) Value() string {
	// TODO: there is room for improvement here to make this more readable (filter out redundant constraints... e.g. <1.0 || < 2.0 should just be < 2.0)
	var str string
	for i, op := range c.OrOperands {
		if i > 0 {
			str += " || "
		}
		str += op.Value()
	}
	return str
}

func (c combinedConstraint) Format() Format {
	format := UnknownFormat
	if len(c.OrOperands) > 0 {
		format = c.OrOperands[0].Format()
	}
	return format
}

func (c combinedConstraint) Satisfied(version *Version) (bool, error) {
	if version == nil {
		return false, fmt.Errorf("cannot evaluate combined constraint with nil version")
	}

	var errs error
	for _, op := range c.OrOperands {
		satisfied, err := op.Satisfied(version)
		if err != nil {
			// OR semantics: a sibling operand may still be satisfied, so keep
			// evaluating and only surface the error if nothing matches.
			errs = errors.Join(errs, fmt.Errorf("error evaluating constraint %s: %w", op, err))
			continue
		}
		if satisfied {
			return true, nil
		}
	}

	return false, errs
}

func uniqueConstraints(constraints ...Constraint) []Constraint {
	var nonNil []Constraint
	seen := strset.New()
	for _, c := range constraints {
		if c == nil || seen.Has(c.Value()) {
			continue
		}
		seen.Add(c.Value())
		nonNil = append(nonNil, c)
	}
	return nonNil
}
