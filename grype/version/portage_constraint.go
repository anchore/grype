package version

import (
	"fmt"
)

type portageConstraint struct {
	raw        string
	expression constraintExpression
}

func newPortageConstraint(raw string) (portageConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return portageConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, newPortageComparator)
	if err != nil {
		return portageConstraint{}, fmt.Errorf("unable to parse portage constraint phrase: %w", err)
	}

	return portageConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func newPortageComparator(unit constraintUnit) (Comparator, error) {
	ver := newPortageVersion(unit.version)
	return &ver, nil
}

func (c portageConstraint) supported(format Format) bool {
	return format == PortageFormat
}

func (c portageConstraint) Satisfied(version *Version) (bool, error) {
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
		return false, NewUnsupportedFormatError(PortageFormat, version.Format)
	}

	if version.rich.portVer == nil {
		return false, fmt.Errorf("no rich portage version given: %+v", version)
	}

	return c.expression.satisfied(version)
}

func (c portageConstraint) String() string {
	if c.raw == "" {
		return "none (portage)"
	}
	return fmt.Sprintf("%s (portage)", c.raw)
}
