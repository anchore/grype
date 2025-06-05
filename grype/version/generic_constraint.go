package version

import (
	"fmt"
	"strings"
)

var _ Constraint = (*genericConstraint)(nil)

type genericConstraint struct {
	raw        string
	expression constraintExpression
	format     Format
}

func newGenericConstraint(raw string, genFn comparatorGenerator, format Format) (genericConstraint, error) {
	constraints, err := newConstraintExpression(raw, genFn)
	if err != nil {
		return genericConstraint{}, err
	}
	return genericConstraint{
		expression: constraints,
		raw:        raw,
		format:     format,
	}, nil
}

func (g genericConstraint) String() string {
	value := "none"
	if g.raw != "" {
		value = g.raw
	}
	return fmt.Sprintf("%s (%s)", value, strings.ToLower(g.format.String()))
}

func (g genericConstraint) Format() Format {
	return g.format
}

func (g genericConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" {
		return true, nil // the empty constraint is always satisfied
	}
	return g.expression.satisfied(version)
}
