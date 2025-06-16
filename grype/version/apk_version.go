package version

import (
	apk "github.com/knqyf263/go-apk-version"
)

var _ Comparator = (*apkVersion)(nil)

type apkVersion struct {
	obj apk.Version
}

func newApkVersion(raw string) (apkVersion, error) {
	ver, err := apk.NewVersion(raw)
	if err != nil {
		return apkVersion{}, err
	}

	return apkVersion{
		obj: ver,
	}, nil
}

func (v apkVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	if o, ok := other.comparator.(apkVersion); ok {
		return v.obj.Compare(o.obj), nil
	}

	return -1, newNotComparableError(ApkFormat, other)
}
