package version

import (
	"fmt"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*golangVersion)(nil)

type golangVersion struct {
	raw    string
	semVer *hashiVer.Version
}

func (g golangVersion) Compare(version *Version) (int, error) {
	if version.Format != GolangFormat {
		return -1, NewUnsupportedFormatError(GolangFormat, version.Format)
	}
	if version.rich.golangVersion == nil {
		return -1, fmt.Errorf("cannot compare version with nil golang version to golang version")
	}
	if version.rich.golangVersion.raw == g.raw {
		return 0, nil
	}
	if version.rich.golangVersion.raw == "(devel)" {
		return -1, fmt.Errorf("cannot compare %s with %s", g.raw, version.rich.golangVersion.raw)
	}

	return version.rich.golangVersion.compare(g), nil
}

func (g golangVersion) compare(o golangVersion) int {
	switch {
	case g.semVer != nil && o.semVer != nil:
		return g.semVer.Compare(o.semVer)
	case g.semVer != nil && o.semVer == nil:
		return 1
	case g.semVer == nil && o.semVer != nil:
		return -1
	default:
		return strings.Compare(g.raw, o.raw)
	}
}

func newGolangVersion(v string) (*golangVersion, error) {
	if v == "(devel)" {
		return nil, ErrUnsupportedVersion
	}
	// go stdlib is reported by syft as a go package with version like "go1.24.1"
	// other versions have "v" as a prefix, which the semver lib handles automatically
	semver, err := hashiVer.NewSemver(strings.TrimPrefix(v, "go"))
	if err != nil {
		return nil, err
	}
	return &golangVersion{
		raw:    v,
		semVer: semver,
	}, nil
}
