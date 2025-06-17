//nolint:dupl
package version

import (
	"fmt"
)

type rpmConstraint struct {
	raw        string
	expression constraintExpression
}

func newRpmConstraint(raw string) (rpmConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return rpmConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, RpmFormat)
	if err != nil {
		return rpmConstraint{}, fmt.Errorf("unable to parse rpm constraint phrase: %w", err)
	}

	return rpmConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func (c rpmConstraint) supported(format Format) bool {
	return format == RpmFormat
}

func (c rpmConstraint) Satisfied(version *Version) (bool, error) {
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
		return false, newUnsupportedFormatError(RpmFormat, version)
	}

	return c.expression.satisfied(version)
}

func (c rpmConstraint) String() string {
	if c.raw == "" {
		return "none (rpm)"
	}
	return fmt.Sprintf("%s (rpm)", c.raw)
}
