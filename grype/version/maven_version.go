package version

import (
	"fmt"

	mvnv "github.com/masahiro331/go-mvn-version"
)

var _ Comparator = (*mavenVersion)(nil)

type mavenVersion struct {
	raw string
	obj mvnv.Version
}

func newMavenVersion(raw string) (mavenVersion, error) {
	ver, err := mvnv.NewVersion(raw)
	if err != nil {
		return mavenVersion{}, fmt.Errorf("could not generate new java version from: %s; %w", raw, err)
	}

	return mavenVersion{
		raw: raw,
		obj: ver,
	}, nil
}

// Compare returns 0 if other == j, 1 if other > j, and -1 if other < j.
// If an error is returned, the int value is -1
func (v mavenVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, fmt.Errorf("cannot compare nil version with %v", other)
	}
	if o, ok := other.comparator.(mavenVersion); ok {
		return v.compare(o.obj)
	}

	return -1, newNotComparableError(MavenFormat, other)
}

func (v mavenVersion) compare(other mvnv.Version) (int, error) {
	if v.obj.Equal(other) {
		return 0, nil
	}
	if v.obj.LessThan(other) {
		return -1, nil
	}
	if v.obj.GreaterThan(other) {
		return 1, nil
	}

	return -1, fmt.Errorf(
		"could not compare java versions: %v with %v",
		other.String(),
		v.obj.String())
}
