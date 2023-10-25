package version

import "fmt"

type javaConstraint struct {
	raw        string
	expression constraintExpression
}

func newJavaConstraint(raw string) (javaConstraint, error) {
	if raw == "" {
		// empty constraints are always satisfied
		return javaConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, newJavaComparator)
	if err != nil {
		return javaConstraint{}, fmt.Errorf("unable to parse java constraint phrase: %w", err)
	}

	return javaConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func newJavaComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newJavaVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}

	return ver, nil
}

func (c javaConstraint) supported(format Format) bool {
	return format == JavaFormat
}

func (c javaConstraint) Satisfied(version *Version) (satisfied bool, err error) {
	if c.raw == "" && version != nil {
		// empty constraints are always satisfied
		return true, nil
	}

	if version == nil {
		if c.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}

		return true, nil
	}

	if !c.supported(version.Format) {
		return false, fmt.Errorf("(java) unsupported format: %s", version.Format)
	}

	if version.rich.javaVer == nil {
		return false, fmt.Errorf("no rich apk version given: %+v", version)
	}

	return c.expression.satisfied(version)
}

func (c javaConstraint) String() string {
	if c.raw == "" {
		return "none (java)"
	}

	return fmt.Sprintf("%s (java)", c.raw)
}
