package version

func newBitnamiConstraint(raw string) (Constraint, error) {
	return newGenericConstraint(raw, BitnamiFormat)
}
