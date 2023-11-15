package version

import "fmt"

var _ Constraint = (*golangConstraint)(nil)

type golangConstraint struct {
	raw        string
	expression constraintExpression
}

func newGolangConstraint(raw string) (golangConstraint, error) {
	constraints, err := newConstraintExpression(raw, newGolangComparator)
	if err != nil {
		return golangConstraint{}, err
	}
	return golangConstraint{
		expression: constraints,
		raw:        raw,
	}, nil
}

func (g golangConstraint) String() string {
	if g.raw == "" {
		return "none (go)"
	}
	return fmt.Sprintf("%s (go)", g.raw)
}

func (g golangConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" {
		return true, nil // the empty constraint is always satisfied
	}
	return g.expression.satisfied(version)
}

func newGolangComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newGolangVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
