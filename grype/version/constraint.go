package version

import (
	"fmt"
	"github.com/scylladb/go-set/strset"
	"strings"
)

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
		return nil, fmt.Errorf("could not find constraint for given Fmt: %s", format)
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

func CombineConstraints(constraints ...Constraint) Constraint {
	constraints = uniqueConstraints(constraints...)

	if len(constraints) == 0 {
		return nil
	}
	if len(constraints) == 1 {
		return constraints[0]
	}

	return combinedConstraint{
		OrOperands: constraints,
	}
}

type combinedConstraint struct {
	OrOperands []Constraint
}

func (c combinedConstraint) String() string {
	return fmt.Sprintf("%s (%s)", c.Value(), strings.ToLower(c.Format().String()))
}

func (c combinedConstraint) Value() string {
	var str string
	for i, op := range c.OrOperands {
		if i > 0 {
			str += " || "
		}
		str += op.Value()
	}
	return str
}

func (c combinedConstraint) Format() Format {
	format := UnknownFormat
	if len(c.OrOperands) > 0 {
		format = c.OrOperands[0].Format()
	}
	return format
}

func (c combinedConstraint) Satisfied(version *Version) (bool, error) {
	if version == nil {
		return false, fmt.Errorf("cannot evaluate combined constraint with nil version")
	}

	for _, op := range c.OrOperands {
		satisfied, err := op.Satisfied(version)
		if err != nil {
			return false, fmt.Errorf("error evaluating constraint %s: %w", op, err)
		}
		if satisfied {
			return true, nil
		}
	}

	return false, nil
}

func uniqueConstraints(constraints ...Constraint) []Constraint {
	var nonNil []Constraint
	seen := strset.New()
	for _, c := range constraints {
		if c == nil || seen.Has(c.Value()) {
			continue
		}
		seen.Add(c.Value())
		nonNil = append(nonNil, c)
	}
	return nonNil
}
