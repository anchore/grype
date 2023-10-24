package version

type javaConstraint struct {
}

func newJavaConstraint() (javaConstraint, error) {
	return javaConstraint{}, nil
}

func (c javaConstraint) supported(format Format) bool {
	return format == JavaFormat
}

func (c javaConstraint) Satisfied(version *Version) (satisfied bool, err error) {
	return satisfied, err
}

func (c javaConstraint) String() string {
	return ""
}
