//nolint:dupl
package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
)

type bitnamiConstraint struct {
	raw string
	// We use Semantic Version for Bitnami constraints, given
	// Bitnami Vulndb uses it
	expression hashiVer.Constraints
}

func newBitnamiConstraint(raw string) (bitnamiConstraint, error) {
	if raw == "" {
		// empty constraints are always satisfied
		return bitnamiConstraint{}, nil
	}

	constraints, err := hashiVer.NewConstraint(raw)
	if err != nil {
		return bitnamiConstraint{}, fmt.Errorf("unable to parse bitnami constraint phrase: %w", err)
	}

	return bitnamiConstraint{
		raw:        raw,
		expression: constraints,
	}, nil
}

func newBitnamiComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newBitnamiVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse constraint version (%s): %w", unit.version, err)
	}

	return ver, nil
}

func (c bitnamiConstraint) supported(format Format) bool {
	return format == BitnamiFormat
}

func (c bitnamiConstraint) Satisfied(version *Version) (bool, error) {
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
		return false, NewUnsupportedFormatError(BitnamiFormat, version.Format)
	}

	if version.rich.semVer == nil {
		return false, fmt.Errorf("no rich bitnami version given: %+v", version)
	}

	return c.expression.Check(version.rich.semVer.verObj), nil
}

func (c bitnamiConstraint) String() string {
	if c.raw == "" {
		return "none (bitnami)"
	}

	return fmt.Sprintf("%s (bitnami)", c.raw)
}
