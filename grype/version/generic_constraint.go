package version

import "fmt"

var _ Constraint = (*genericConstraint)(nil)

type genericConstraint struct {
	raw        string
	expression constraintExpression
	name       string
}

func newGenericConstraint(raw string, genFn comparatorGenerator, name string) (genericConstraint, error) {
	constraints, err := newConstraintExpression(raw, genFn)
	if err != nil {
		return genericConstraint{}, err
	}
	return genericConstraint{
		expression: constraints,
		raw:        raw,
		name:       name,
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
