package version

import "fmt"

var _ Constraint = (*pep440Constraint)(nil)

func newPep440Constraint(raw string) (pep440Constraint, error) {
	if raw == "" {
		return pep440Constraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, PythonFormat)
	if err != nil {
		return pep440Constraint{}, fmt.Errorf("unable to parse pep440 constrain phrase %w", err)
	}

	return pep440Constraint{
		expression: constraints,
		raw:        raw,
	}, nil
}

type pep440Constraint struct {
	raw        string
	expression constraintExpression
}

func (p pep440Constraint) String() string {
	if p.raw == "" {
		return "none (python)"
	}
	return fmt.Sprintf("%s (python)", p.raw)
}

func (p pep440Constraint) Satisfied(version *Version) (bool, error) {
	if p.raw == "" && version != nil {
		// an empty constraint is always satisfied
		return true, nil
	} else if version == nil {
		if p.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}
	if version.Format != PythonFormat {
		return false, newUnsupportedFormatError(PythonFormat, version)
	}

	return p.expression.satisfied(version)
}
