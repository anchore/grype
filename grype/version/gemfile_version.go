package version

import (
	"fmt"
	"strings"
)

type gemfileVersion struct {
	// keeping the raw version for transparency,
	// but its value might change to fit semVer standards: https://semver.org/
	raw    string
	semVer *semanticVersion
}

// Gemfile.lock versions may have "{cpu}-{os}" or "{cpu}-{os}-{version}"
// after the semvVer, for example, 12.2.1-alpha-x86_64-darwin-8, where `2.2.1-alpha`
// is a valid and comparable semVer, and `x86_64-darwin-8` is not a semVer due to
// the underscore. Also, we can't sort based on arch and OS in a way that make sense
// for versions. SemVer is a characteristic of the code, not which arch OS it runs on.
//
// CPU is the most structured value present in gemfile.lock versions, we use it
// to split the version info in half, the first half has semVer, and
// the second half has arch and OS which we ignore.
func extractSemVer(raw string) string {
	lower := strings.ToLower(raw)

	cpus := []string{"-x86", "-x86_64", "-universal", "-arm", "-armv5", "-armv6", "-armv7"}
	for _, cpu := range cpus {
		vals := strings.SplitN(lower, cpu, 2)
		if len(vals) == 2 {
			return vals[0]
		}
	}

	return raw
}

func newGemfileVersion(raw string) (*gemfileVersion, error) {
	cleaned := extractSemVer(raw)
	semVer, err := newSemanticVersion(cleaned)
	if err != nil {
		return nil, fmt.Errorf("unable to crate gemfile version obj: %w", err)
	}
	return &gemfileVersion{
		raw:    raw,
		semVer: semVer,
	}, nil
}

func (g *gemfileVersion) Compare(other *Version) (int, error) {
	if other.Format != GemfileFormat {
		return -1, fmt.Errorf("unable to compare Gemfile version to given format: %s", other.Format)
	}
	if other.rich.gemfileVer == nil || other.rich.gemfileVer.semVer == nil {
		return -1, fmt.Errorf("given empty gemfileVersion object")
	}

	return other.rich.gemfileVer.semVer.verObj.Compare(g.semVer.verObj), nil
}
