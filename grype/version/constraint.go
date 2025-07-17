package version

import "fmt"

type Constraint interface {
	fmt.Stringer
	Value() string
	Format() Format
	Satisfied(*Version) (bool, error)
}

func GetConstraint(constStr string, format Format) (Constraint, error) {
	var c Constraint
	var err error

	switch format {
	case ApkFormat:
		c, err = newGenericConstraint(ApkFormat, constStr)
	case SemanticFormat:
		c, err = newGenericConstraint(SemanticFormat, constStr)
	case BitnamiFormat:
		c, err = newGenericConstraint(BitnamiFormat, constStr)
	case GemFormat:
		c, err = newGenericConstraint(GemFormat, constStr)
	case DebFormat:
		c, err = newGenericConstraint(DebFormat, constStr)
	case GolangFormat:
		c, err = newGenericConstraint(GolangFormat, constStr)
	case MavenFormat:
		c, err = newGenericConstraint(MavenFormat, constStr)
	case RpmFormat:
		c, err = newGenericConstraint(RpmFormat, constStr)
	case PythonFormat:
		c, err = newGenericConstraint(PythonFormat, constStr)
	case KBFormat:
		c, err = newKBConstraint(constStr)
	case PortageFormat:
		c, err = newGenericConstraint(PortageFormat, constStr)
	case JVMFormat:
		c, err = newGenericConstraint(JVMFormat, constStr)
	case UnknownFormat:
		c, err = newFuzzyConstraint(constStr, "unknown")
	default:
		return nil, fmt.Errorf("could not find constraint for given format: %s", format)
	}

	return c, err
}

// MustGetConstraint is meant for testing only, do not use within the library
func MustGetConstraint(constStr string, format Format) Constraint {
	c, err := GetConstraint(constStr, format)
	if err != nil {
		panic(err)
	}
	return c
}
