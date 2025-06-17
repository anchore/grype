package version

import (
	"fmt"
)

type Constraint interface {
	fmt.Stringer
	Satisfied(*Version) (bool, error)
}

type constraint struct {
	Format     Format
	Raw        string
	constraint Constraint
}

func GetConstraint(constStr string, format Format) (Constraint, error) {
	var c Constraint
	var err error

	switch format {
	case ApkFormat:
		c, err = newApkConstraint(constStr)
	case SemanticFormat:
		c, err = newSemanticConstraint(constStr)
	case BitnamiFormat:
		c, err = newBitnamiConstraint(constStr)
	case GemFormat:
		c, err = newGemfileConstraint(constStr)
	case DebFormat:
		c, err = newDebConstraint(constStr)
	case GolangFormat:
		c, err = newGolangConstraint(constStr)
	case MavenFormat:
		c, err = newMavenConstraint(constStr)
	case RpmFormat:
		c, err = newRpmConstraint(constStr)
	case PythonFormat:
		c, err = newPep440Constraint(constStr)
	case KBFormat:
		c, err = newKBConstraint(constStr)
	case PortageFormat:
		c, err = newPortageConstraint(constStr)
	case JVMFormat:
		c, err = newJvmConstraint(constStr)
	case UnknownFormat:
		c, err = newFuzzyConstraint(constStr, "unknown")
	default:
		return nil, fmt.Errorf("could not find constraint for given format: %s", format)
	}

	return constraint{
		Format:     format,
		Raw:        constStr,
		constraint: c,
	}, err
}

// MustGetConstraint is meant for testing only, do not use within the library
func MustGetConstraint(constStr string, format Format) Constraint {
	constraint, err := GetConstraint(constStr, format)
	if err != nil {
		panic(err)
	}
	return constraint
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

func (c constraint) String() string {
	return c.Raw
}

func (c constraint) Satisfied(version *Version) (bool, error) {
	return c.constraint.Satisfied(version)
}
