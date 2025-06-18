package version

import (
	"fmt"
	"strings"
)

var _ Constraint = (*genericConstraint)(nil)

type genericConstraint struct {
	raw        string
	expression simpleRangeExpression
	format     Format
}

func newGenericConstraint(format Format, raw string) (genericConstraint, error) {
	constraints, err := parseRangeExpression(raw)
	if err != nil {
		return genericConstraint{}, invalidFormatError(format, raw, err)
	}
	return genericConstraint{
		expression: constraints,
		raw:        raw,
		format:     format,
	}, nil
}

func (g genericConstraint) String() string {
	value := "none"
	if g.raw != "" {
		value = g.raw
	}
	return fmt.Sprintf("%s (%s)", value, strings.ToLower(g.format.String()))
}

func (g genericConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" && version != nil {
		// empty constraints are always satisfied
		return true, nil
	}
	if version == nil {
		if g.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}
	if version.Format != g.format {
		return false, newUnsupportedFormatError(g.format, version)
	}
	return g.expression.satisfied(g.format, version)
}
