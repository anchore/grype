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
		return apkVersion{}, invalidFormatError(ApkFormat, raw, err)
	}

	return apkVersion{
		obj: ver,
	}, nil
}

func (v apkVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	apkVer, err := newApkVersion(other.Raw)
	if err != nil {
		return -1, err
	}

	return v.obj.Compare(apkVer.obj), nil
}
