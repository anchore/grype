//nolint:dupl
package version

import "fmt"

type debConstraint struct {
	raw        string
	expression constraintExpression
}

func newDebConstraint(raw string) (debConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return debConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, DebFormat)
	if err != nil {
		return debConstraint{}, invalidFormatError(DebFormat, raw, err)
	}
	return debConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func (c debConstraint) supported(format Format) bool {
	return format == DebFormat
}

func (c debConstraint) Satisfied(version *Version) (bool, error) {
	if c.raw == "" && version != nil {
		// an empty constraint is always satisfied
		return true, nil
	} else if version == nil {
		if c.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}

	if !c.supported(version.Format) {
		return false, newUnsupportedFormatError(DebFormat, version)
	}

	return c.expression.satisfied(version)
}

func (c debConstraint) String() string {
	if c.raw == "" {
		return "none (deb)"
	}
	return fmt.Sprintf("%s (deb)", c.raw)
}
