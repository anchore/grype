package version

import "fmt"

type kbConstraint struct {
	raw        string
	expression simpleRangeExpression
}

func newKBConstraint(raw string) (kbConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return kbConstraint{}, nil
	}

	constraints, err := parseRangeExpression(raw)
	if err != nil {
		return kbConstraint{}, fmt.Errorf("unable to parse kb constraint phrase: %w", err)
	}

	return kbConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
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

	if version.Format != KBFormat {
		return false, newUnsupportedFormatError(KBFormat, version)
	}

	return c.expression.satisfied(KBFormat, version)
}

func (c kbConstraint) String() string {
	if c.raw == "" {
		return fmt.Sprintf("%q (kb)", c.raw) // with quotes
	}
	return fmt.Sprintf("%s (kb)", c.raw) // no quotes
}
