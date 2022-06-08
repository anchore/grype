package version

import (
	"fmt"

	hashiVer "github.com/anchore/go-version"
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
	semConst semanticConstraint
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
	semConst.checker = gemVerifier
	return gemfileConstraint{semConst: semConst}, nil
}

func gemVerifier(constraint hashiVer.Constraints, version *Version) (bool, error) {
	if GemfileFormat != version.Format {
		return false, fmt.Errorf("(gemfile) unsupported format: %s", version.Format)
	}

	if version.rich.gemfileVer == nil {
		return false, fmt.Errorf("no gemfile version given: %+v", version)
	}
	return constraint.Check(version.rich.gemfileVer.semVer.verObj), nil
}

func (g gemfileConstraint) Satisfied(version *Version) (bool, error) {
	return g.semConst.Satisfied(version)
}

func (g gemfileConstraint) String() string {
	if g.semConst.raw == "" {
		return "none (gemfile)"
	}
	return fmt.Sprintf("%s (gemfile)", g.semConst.raw)
}
