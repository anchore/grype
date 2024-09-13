package version

import "fmt"

var _ Constraint = (*jvmConstraint)(nil)

type jvmConstraint struct {
	raw        string
	expression constraintExpression
}

func newJvmConstraint(raw string) (jvmConstraint, error) {
	constraints, err := newConstraintExpression(raw, newJvmComparator)
	if err != nil {
		return jvmConstraint{}, err
	}
	return jvmConstraint{
		expression: constraints,
		raw:        raw,
	}, nil
}

func (g jvmConstraint) String() string {
	if g.raw == "" {
		return "none (jvm)"
	}
	return fmt.Sprintf("%s (jvm)", g.raw)
}

func (g jvmConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" {
		return true, nil // the empty constraint is always satisfied
	}
	return g.expression.satisfied(version)
}

func newJvmComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newJvmVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
