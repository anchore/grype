package version

import (
	"fmt"
	"strings"
)

var _ Constraint = (*genericConstraint)(nil)

type genericConstraint struct {
	raw        string
	expression constraintExpression
	name       string
}

func newGenericConstraint(raw string, format Format) (genericConstraint, error) {
	constraints, err := newConstraintExpression(raw, format)
	if err != nil {
		return genericConstraint{}, err
	}
	return genericConstraint{
		expression: constraints,
		raw:        raw,
		name:       strings.ToLower(format.String()),
	}, nil
}

func (g genericConstraint) String() string {
	value := "none"
	if g.raw != "" {
		value = g.raw
	}
	return fmt.Sprintf("%s (%s)", value, g.name)
}

func (g genericConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" {
		return true, nil // the empty constraint is always satisfied
	}
	return g.expression.satisfied(version)
}
