package version

import (
	"fmt"
)

type rpmConstraint struct {
	raw         string
	versions    []rpmVersion
	constraints []constraintPart
}

func newRpmConstraint(raw string) (rpmConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return rpmConstraint{}, nil
	}

	constraints, err := splitConstraintPhrase(raw)
	if err != nil {
		return rpmConstraint{}, fmt.Errorf("unable to parse deb constraint phrase: %w", err)
	}
	versions := make([]rpmVersion, len(constraints))

	for idx, c := range constraints {
		ver, err := newRpmVersion(c.version)
		if err != nil {
			return rpmConstraint{}, fmt.Errorf("could not parse constraint version (%s): %w", c.version, err)
		}
		versions[idx] = ver
	}
	return rpmConstraint{
		raw:         raw,
		versions:    versions,
		constraints: constraints,
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
		return false, fmt.Errorf("(rpm) unsupported format: %s", version.Format)
	}

	if version.rich.rpmVer == nil {
		return false, fmt.Errorf("no rich rpm version given: %+v", version)
	}

	var result = true
	for idx, constraint := range c.constraints {
		ver := c.versions[idx]
		result = result && constraint.Satisfied(version.rich.rpmVer.Compare(ver))
	}

	return result, nil
}

func (c rpmConstraint) String() string {
	if c.raw == "" {
		return "none (rpm)"
	}
	return fmt.Sprintf("%s (rpm)", c.raw)
}
