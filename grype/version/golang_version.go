package version

import (
	"fmt"
	"strings"

	hashiVer "github.com/anchore/go-version"
)

var _ Comparator = (*golangVersion)(nil)

type golangVersion struct {
	raw string
	obj *hashiVer.Version
}

func newGolangVersion(v string) (golangVersion, error) {
	if v == "(devel)" {
		return golangVersion{}, ErrUnsupportedVersion
	}

	// Invalid Semver fix ups

	// go stdlib is reported by syft as a go package with version like "go1.24.1"
	// other versions have "v" as a prefix, which the semver lib handles automatically
	fixedUp := strings.TrimPrefix(v, "go")

	// go1.24 creates non-dot separated build metadata fields, e.g. +incompatible+dirty
	// Fix up as per semver spec
	before, after, found := strings.Cut(fixedUp, "+")
	if found {
		fixedUp = before + "+" + strings.ReplaceAll(after, "+", ".")
	}

	semver, err := hashiVer.NewSemver(fixedUp)
	if err != nil {
		return golangVersion{}, err
	}
	return golangVersion{
		raw: v,
		obj: semver,
	}, nil
}

func (g golangVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, ok := other.comparator.(golangVersion)
	if !ok {
		return -1, newNotComparableError(GolangFormat, other)
	}

	if o.raw == g.raw {
		return 0, nil
	}

	if o.raw == "(devel)" {
		return -1, fmt.Errorf("cannot compare a non-development version %q with a default development version of %q", g.raw, o.raw)
	}

	return g.compare(o), nil
}

func (g golangVersion) compare(o golangVersion) int {
	switch {
	case g.obj != nil && o.obj != nil:
		return g.obj.Compare(o.obj)
	case g.obj != nil && o.obj == nil:
		return 1
	case g.obj == nil && o.obj != nil:
		return -1
	default:
		return strings.Compare(g.raw, o.raw)
	}
}
