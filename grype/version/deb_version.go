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
		return debVersion{}, invalidFormatError(DebFormat, raw, err)
	}
	return debVersion{
		obj: ver,
	}, nil
}

func (v debVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newDebVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	return v.obj.Compare(o.obj), nil
}
