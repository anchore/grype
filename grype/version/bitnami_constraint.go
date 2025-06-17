package version

func newBitnamiConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, BitnamiFormat)
}

// func newBitnamiComparator(unit constraintUnit) (Comparator, error) {
//	ver, err := newBitnamiVersion(unit.rawVersion)
//	if err != nil {
//		return nil, fmt.Errorf("unable to parse bitnami constraint version (%s): %w", unit.rawVersion, err)
//	}
//	return ver, nil
//}
