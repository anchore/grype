package version

import (
	"fmt"
)

type Constraint interface {
	fmt.Stringer
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
		c, err = newGenericConstraint(KBFormat, constStr)
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

// NonFatalConstraintError should be used any time an unexpected but recoverable condition is encountered while
// checking version constraint satisfaction. The error should get returned by any implementer of the Constraint
// interface. If returned by the Satisfied method on the Constraint interface, this error will be caught and
// logged as a warning in the FindMatchesByPackageDistro function in grype/matcher/common/distro_matchers.go
type NonFatalConstraintError struct {
	constraint Constraint
	version    *Version
	message    string
}

func (e NonFatalConstraintError) Error() string {
	return fmt.Sprintf("Matching raw constraint %s against version %s caused a non-fatal error: %s", e.constraint, e.version, e.message)
}
