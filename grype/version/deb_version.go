package version

import (
	deb "github.com/knqyf263/go-deb-version"
)

var _ Comparator = (*debVersion)(nil)

type debVersion struct {
	obj deb.Version
}

func newDebVersion(raw string) (debVersion, error) {
	ver, err := deb.NewVersion(raw)
	if err != nil {
		return debVersion{}, err
	}
	return debVersion{
		obj: ver,
	}, nil
}

func (v debVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	if o, ok := other.comparator.(debVersion); ok {
		return v.obj.Compare(o.obj), nil
	}

	return -1, newNotComparableError(DebFormat, other)
}
