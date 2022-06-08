package version

import (
	"fmt"
)

// Gemfile.lock doesn't follow a spec, the best documentation comes
// from `gem help platform`: The platform you pass must match "#{cpu}-#{os}" or
// "#{cpu}-#{os}-#{version}".  On mswin
// platforms, the version is the compiler version, not the OS version.  (Ruby
// compiled with VC6 uses "60" as the compiler version, VC8 uses "80".)
// Ruby Gemfile.locks, created by bundler, version string may include
// chars that are not valid semantic versions, such as underscore (_ in 1.13.1-x86_64-linux),
// also the arch and OS info would be read as a pre-release value, which is incorrect.
type gemfileConstraint struct {
	semanticConstraint
}

func newGemfileConstraint(constStr string) (gemfileConstraint, error) {
	if constStr == "" {
		// an empty constraint is always satisfied
		return gemfileConstraint{}, nil
	}

	semConst, err := newSemanticConstraint(constStr)
	if err != nil {
		return gemfileConstraint{}, err
	}
	return gemfileConstraint{semConst}, nil
}

func (g gemfileConstraint) supported(format Format) bool {
	return format == GemfileFormat
}

func (g gemfileConstraint) Satisfied(version *Version) (bool, error) {
	if g.raw == "" && version != nil {
		// an empty constraint is always satisfied
		return true, nil
	} else if version == nil {
		if g.raw != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}

	if !g.supported(version.Format) {
		return false, fmt.Errorf("(gemfile) unsupported format: %s", version.Format)
	}

	if version.rich.gemfileVer == nil {
		return false, fmt.Errorf("no rich gemfile version given: %+v", version)
	}

	return g.constraint.Check(version.rich.gemfileVer.semVer.verObj), nil
}

func (g gemfileConstraint) String() string {
	if g.raw == "" {
		return "none (gemfile)"
	}
	return fmt.Sprintf("%s (gemfile)", g.raw)
}
