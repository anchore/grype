package version

import (
	"fmt"
)

type kbConstraint struct {
	raw        string
	expression constraintExpression
}

func newKBConstraint(raw string) (kbConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return kbConstraint{}, nil
	}

	constraints, err := newConstraintExpression(raw, newKBComparator)
	if err != nil {
		return kbConstraint{}, fmt.Errorf("unable to parse kb constraint phrase: %w", err)
	}

	return kbConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func newKBComparator(unit constraintUnit) (Comparator, error) {
	// XXX unit.version is probably not needed because newKBVersion doesn't do anything
	ver := newKBVersion(unit.version)
	return &ver, nil
}

func (c kbConstraint) supported(format Format) bool {
	return format == KBFormat
}

func (c kbConstraint) Satisfied(version *Version) (bool, error) {
	if c.raw == "" {
		// an empty constraint is never satisfied
		return false, &NonFatalConstraintError{
			constraint: c,
			version:    version,
			message:    "Unexpected data in DB: Empty raw version constraint.",
		}
	}

	if version == nil {
		return true, nil
	}

	if !c.supported(version.Format) {
		return false, NewUnsupportedFormatError(KBFormat, version.Format)
	}

	return c.expression.satisfied(version)
}

func (c kbConstraint) String() string {
	if c.raw == "" {
		return fmt.Sprintf("%q (kb)", c.raw)
	}
	return fmt.Sprintf("%s (kb)", c.raw)
}
