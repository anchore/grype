package version

import (
	"fmt"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

// bundler >= 2.2.0 adds metadata suffixes to each package version
// these values are removed to create clean/normalized semver value,
// while the orignal value is preserved in raw.
var gemfileNormalizer = strings.NewReplacer("-x86_64", "", "-darwin", "", "-linux", "", "-x86", "", ".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")

type gemfileConstraint struct {
	raw        string
	constraint hashiVer.Constraints
}

func newGemfileConstraint(raw string) (gemfileConstraint, error) {
	if raw == "" {
		// an empty constraint is always satisfied
		return gemfileConstraint{}, nil
	}

	normalized := gemfileNormalizer.Replace(raw)

	constraints, err := hashiVer.NewConstraint(normalized)
	if err != nil {
		return gemfileConstraint{}, err
	}
	return gemfileConstraint{
		raw:        raw,
		constraint: constraints,
	}, nil
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
		return false, fmt.Errorf("no gemfile version given: %+v", version)
	}
	return g.constraint.Check(version.rich.gemfileVer.verObj), nil
}

func (g gemfileConstraint) String() string {
	if g.raw == "" {
		return "none (gemfile)"
	}
	return fmt.Sprintf("%s (gemfile)", g.raw)
}
