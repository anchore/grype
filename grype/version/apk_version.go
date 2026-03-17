package version

import (
	apk "github.com/knqyf263/go-apk-version"
)

var _ Comparator = (*apkVersion)(nil)

type apkVersion struct {
	obj apk.Version
}

func newApkVersion(raw string) (apkVersion, error) {
	ver, err := apk.NewVersion(trimLeadingV(raw))
	if err != nil {
		return apkVersion{}, invalidFormatError(ApkFormat, raw, err)
	}

	return apkVersion{
		obj: ver,
	}, nil
}

// trimLeadingV removes a single leading 'v' or 'V' prefix only if it's followed by a digit.
// This allows versions like "v1.5.0" to be treated as "1.5.0" while preserving other strings as-is.
func trimLeadingV(raw string) string {
	if len(raw) >= 2 && (raw[0] == 'v' || raw[0] == 'V') && raw[1] >= '0' && raw[1] <= '9' {
		return raw[1:]
	}
	return raw
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
