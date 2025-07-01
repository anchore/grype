package version

import "fmt"

type kbConstraint struct {
	Raw        string
	Expression simpleRangeExpression
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
		Raw:        raw,
		Expression: constraints,
	}, nil
}

func (c kbConstraint) Satisfied(version *Version) (bool, error) {
	if c.Raw == "" {
		// an empty constraint is never satisfied
		return false, &NonFatalConstraintError{
			constraint: c,
			version:    version,
			message:    "unexpected data in DB: empty raw version constraint",
		}
	}

	if version == nil {
		return true, nil
	}

	if version.Format != KBFormat {
		return false, newUnsupportedFormatError(KBFormat, version)
	}

	return c.Expression.satisfied(KBFormat, version)
}

func (c kbConstraint) Format() Format {
	return KBFormat
}

func (c kbConstraint) String() string {
	if c.Raw == "" {
		return fmt.Sprintf("%q (kb)", c.Raw) // with quotes
	}
	return fmt.Sprintf("%s (kb)", c.Raw) // no quotes
}

func (c kbConstraint) Value() string {
	return c.Raw
}
