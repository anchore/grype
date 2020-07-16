package version

import (
	"fmt"

	deb "github.com/knqyf263/go-deb-version"
)

func newDebVersion(raw string) (*deb.Version, error) {
	ver, err := deb.NewVersion(raw)
	if err != nil {
		return nil, err
	}
	return &ver, nil
}

type debConstraint struct {
	raw         string
	versions    []*deb.Version
	constraints []constraintPart
}

func newDebConstraint(raw string) (debConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return debConstraint{}, nil
	}

	constraints, err := splitConstraintPhrase(raw)
	if err != nil {
		return debConstraint{}, fmt.Errorf("unable to parse deb constraint phrase: %w", err)
	}
	versions := make([]*deb.Version, len(constraints))

	for idx, c := range constraints {
		ver, err := newDebVersion(c.version)
		if err != nil {
			return debConstraint{}, fmt.Errorf("unable to parse constraint version (%s): %w", c.version, err)
		}
		versions[idx] = ver
	}
	return debConstraint{
		raw:         raw,
		versions:    versions,
		constraints: constraints,
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
		return false, fmt.Errorf("(deb) unsupported format: %s", version.Format)
	}

	if version.rich.debVer == nil {
		return false, fmt.Errorf("no rich deb version given: %+v", version)
	}

	var result = true
	for idx, constraint := range c.constraints {
		ver := c.versions[idx]
		result = result && constraint.Satisfied(version.rich.debVer.Compare(*ver))
	}

	return result, nil
}

func (c debConstraint) String() string {
	if c.raw == "" {
		return "none (deb)"
	}
	return fmt.Sprintf("%s (deb)", c.raw)
}
