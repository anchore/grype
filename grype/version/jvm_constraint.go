package version

import "fmt"

func newJvmConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, newJvmComparator, "jvm")
}

func newJvmComparator(unit constraintUnit) (Comparator, error) {
	ver, err := newJvmVersion(unit.version)
	if err != nil {
		return nil, fmt.Errorf("unable to parse JVM constraint version (%s): %w", unit.version, err)
	}
	return ver, nil
}
