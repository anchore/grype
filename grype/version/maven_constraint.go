package version

import "fmt"

type mavenConstraint struct {
	raw        string
	expression constraintExpression
}

func newMavenConstraint(raw string) (mavenConstraint, error) {
	if raw == "" {
		// empty constraints are always satisfied
		return mavenConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, newMavenComparator)
	if err != nil {
		return mavenConstraint{}, fmt.Errorf("unable to parse maven constraint phrase: %w", err)
	}

	return mavenConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func newMavenComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newMavenVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}

	return ver, nil
}

func (c mavenConstraint) supported(format Format) bool {
	return format == MavenFormat
}

func (c mavenConstraint) Satisfied(version *Version) (satisfied bool, err error) {
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
		return false, NewUnsupportedFormatError(MavenFormat, version.Format)
	}

	if version.rich.mavenVer == nil {
		return false, fmt.Errorf("no rich apk version given: %+v", version)
	}

	return c.expression.satisfied(version)
}

func (c mavenConstraint) String() string {
	if c.raw == "" {
		return "none (maven)"
	}

	return fmt.Sprintf("%s (maven)", c.raw)
}
