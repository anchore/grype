package version

import (
	"regexp"
	"strconv"
)

var _ Comparator = (*echoVersion)(nil)

// echoBuildRe captures the N in Echo's "+echo.N" version suffix.
var echoBuildRe = regexp.MustCompile(`\+echo\.(\d+)`)

// echoVersion compares Echo-patched builds of SemVer-versioned packages
// (e.g. npm). SemVer excludes build metadata from precedence, so
// "3.1.9+echo.1" and "3.1.9+echo.2" compare equal under semantic rules and
// successive Echo builds of the same upstream version cannot be ordered.
// This comparator applies semantic ordering first and breaks ties on the
// echo build number (a version without the suffix has build 0):
// 3.1.9 < 3.1.9+echo.1 < 3.1.9+echo.2 < 3.1.10.
type echoVersion struct {
	semVer semanticVersion
	build  int
}

func newEchoVersion(raw string) (echoVersion, error) {
	semVer, err := newSemanticVersion(raw, false)
	if err != nil {
		return echoVersion{}, err
	}
	build := 0
	if m := echoBuildRe.FindStringSubmatch(raw); m != nil {
		build, err = strconv.Atoi(m[1])
		if err != nil {
			return echoVersion{}, invalidFormatError(EchoFormat, raw, err)
		}
	}
	return echoVersion{semVer: semVer, build: build}, nil
}

func (v echoVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newEchoVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	if result := v.semVer.obj.Compare(o.semVer.obj); result != 0 {
		return result, nil
	}
	switch {
	case v.build < o.build:
		return -1, nil
	case v.build > o.build:
		return 1, nil
	}
	return 0, nil
}
