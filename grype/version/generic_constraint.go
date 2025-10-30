package version

import (
	"fmt"
	"strings"
)

var _ Constraint = (*genericConstraint)(nil)

type genericConstraint struct {
	Raw        string
	Expression simpleRangeExpression
	Fmt        Format
}

func newGenericConstraint(format Format, raw string) (genericConstraint, error) {
	constraints, err := parseRangeExpression(raw)
	if err != nil {
		return genericConstraint{}, invalidFormatError(format, raw, err)
	}
	return genericConstraint{
		Expression: constraints,
		Raw:        raw,
		Fmt:        format,
	}, nil
}

func (g genericConstraint) String() string {
	value := g.Value()
	if g.Raw == "" {
		value = "none"
	}
	return fmt.Sprintf("%s (%s)", value, strings.ToLower(g.Fmt.String()))
}

func (g genericConstraint) Value() string {
	return g.Raw
}

func (g genericConstraint) Format() Format {
	return g.Fmt
}

func (g genericConstraint) Satisfied(version *Version) (bool, error) {
	if g.Raw == "" && version != nil {
		// empty constraints are always satisfied
		return true, nil
	}
	if version == nil {
		if g.Raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}
	// we want to prevent against two known formats that are different from being compared.
	// if the passed in version is unknown, we allow the comparison to proceed
	if version.Format != g.Fmt && version.Format != UnknownFormat {
		return false, newUnsupportedFormatError(g.Fmt, version)
	}
	return g.Expression.satisfied(g.Fmt, version)
}
