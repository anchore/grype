package version

import (
	"regexp"

	apk "github.com/knqyf263/go-apk-version"
)

var _ Comparator = (*apkVersion)(nil)

// apkReleaseSuffix matches the "-rN" package release that every built apk carries.
var apkReleaseSuffix = regexp.MustCompile(`-r\d+$`)

type apkVersion struct {
	raw string
	obj apk.Version
}

func newApkVersion(raw string) (apkVersion, error) {
	trimmed := trimLeadingV(raw)
	ver, err := apk.NewVersion(trimmed)
	if err != nil {
		return apkVersion{}, invalidFormatError(ApkFormat, raw, err)
	}

	return apkVersion{
		raw: trimmed,
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

// CompareWithConfig compares two apk versions using the provided comparison configuration. The
// config controls what happens when the package version (v) has no release suffix and the
// constraint (other) has one:
//   - "zero" strategy: the package version is compared as "-r0"
//   - "strict" (or empty) strategy: apk-tools ordering, where a bare version sorts below "-r0"
//
// Only the package side is filled in. A constraint without a release suffix already compares
// correctly against real packages, which always have one.
func (v apkVersion) CompareWithConfig(other *Version, cfg ComparisonConfig) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newApkVersion(other.Raw)
	if err != nil {
		return -1, err
	}

	if apkReleaseSuffix.MatchString(v.raw) || !apkReleaseSuffix.MatchString(o.raw) {
		return v.obj.Compare(o.obj), nil
	}

	if cfg.MissingApkReleaseStrategy != MissingApkReleaseStrategyZero {
		return v.obj.Compare(o.obj), nil
	}

	withRelease, err := apk.NewVersion(v.raw + "-r0")
	if err != nil {
		// fall back to the plain comparison if the filled-in version doesn't parse
		return v.obj.Compare(o.obj), nil
	}
	return withRelease.Compare(o.obj), nil
}
