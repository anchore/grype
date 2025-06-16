package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
)

type semanticConstraint struct {
	raw        string
	constraint hashiVer.Constraints
}

func newSemanticConstraint(constStr string) (semanticConstraint, error) {
	if constStr == "" {
		// an empty constraint is always satisfied
		return semanticConstraint{}, nil
	}

	constraints, err := hashiVer.NewConstraint(constStr)
	if err != nil {
		return semanticConstraint{}, err
	}
	return semanticConstraint{
		raw:        constStr,
		constraint: constraints,
	}, nil
}

func (c semanticConstraint) supported(format Format) bool {
	// gemfiles are a case of semantic version combined with non-semver
	// and that doesn't work well. Gemfile_version.go extracts the semVer
	// portion and makes a semVer object that is compatible with
	// these constraints. In practice two formats (semVer, gem version) follow semVer,
	// but one of them needs extra cleanup to function (gem).
	// Bitnami is a special case that uses semantic versioning given semVer
	// is used on the Bitnami Vulndb but it's not used on the Bitnami packages.
	return format == SemanticFormat || format == BitnamiFormat
}

func (c semanticConstraint) Satisfied(version *Version) (bool, error) {
	if c.raw == "" && version != nil {
		// an empty constraint is always satisfied
		return true, nil
	} else if version == nil {
		if c.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}

	if !c.supported(version.Format) {
		return false, newUnsupportedFormatError(SemanticFormat, version)
	}

	semver, ok := version.comparator.(semanticVersion)
	if !ok {
		return false, fmt.Errorf("cannot compare %T with %T", c, version.comparator)
	}

	return c.constraint.Check(semver.obj), nil
}

func (c semanticConstraint) String() string {
	if c.raw == "" {
		return "none (semver)"
	}
	return fmt.Sprintf("%s (semver)", c.raw)
}
