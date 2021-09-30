package version

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type rpmVersion struct {
	epoch   int
	version string
	release string
}

func newRpmVersion(raw string) (rpmVersion, error) {
	var fields = strings.SplitN(raw, ":", 2)
	var err error
	// When the epoch is not included, should be considered to be 0 during comparisons
	// see https://github.com/rpm-software-management/rpm/issues/450
	// But, often the inclusion of the epoch in vuln databases or source RPM filenames is not consistent
	// so, represent a missing epoch as an invalid epoch value: -1.
	// this allows the comparison logic itself to determine if it should use a zero or another value
	// which supports more flexible comparison options because the version creation is not lossy
	var epoch = -1
	var remaining = raw

	if len(fields) > 1 {
		// there is an epoch
		epochStr := strings.TrimLeft(fields[0], " ")
		epoch, err = strconv.Atoi(epochStr)
		if err != nil {
			return rpmVersion{}, fmt.Errorf("unable to parse epoch (%s): %w", epochStr, err)
		}
		remaining = fields[1]
	}

	fields = strings.SplitN(remaining, "-", 2)
	var ver = fields[0]
	var release string
	if len(fields) > 1 {
		// there is a release
		release = fields[1]
	}

	return rpmVersion{
		epoch:   epoch,
		version: ver,
		release: release,
	}, nil
}

func (v *rpmVersion) Compare(other *Version) (int, error) {
	if other.Format != RpmFormat {
		return -1, fmt.Errorf("unable to compare rpm to given format: %s", other.Format)
	}
	if other.rich.rpmVer == nil {
		return -1, fmt.Errorf("given empty rpmVersion object")
	}

	return other.rich.rpmVer.compare(*v), nil
}

// Compare returns 0 if v == v2, -1 if v < v2, and +1 if v > v2.
// This a pragmatic adaptation of comparison for the messy data
// encountered in vuln scanning. If epochs are present and explicit
// (e.g. >= 0) in both verions then they are ignored for the comparison.
// For a rpm spec-compliant comparison, see strictCompare() instead
func (v rpmVersion) compare(v2 rpmVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}

	// Only compare epochs if both are present and explicit
	if v.epoch >= 0 && v2.epoch >= 0 {
		epochResult := compareEpochs(v.epoch, v2.epoch)
		if epochResult != 0 {
			return epochResult
		}
	}

	ret := compareRpmVersions(v.version, v2.version)
	if ret != 0 {
		return ret
	}

	return compareRpmVersions(v.release, v2.release)
}

// Strict comparison, defaulting epoch < 0 to be 0 per rpm spec
// Compare returns 0 if v == v2, -1 if v < v2, and +1 if v > v2.
func (v rpmVersion) strictCompare(v2 rpmVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}

	vEpoch := 0
	v2Epoch := 0

	// Apply default logic if epoch is not set (-1)
	if v.epoch > 0 {
		vEpoch = v.epoch
	}

	if v2.epoch > 0 {
		v2Epoch = v.epoch
	}

	epochResult := compareEpochs(vEpoch, v2Epoch)
	if epochResult != 0 {
		return epochResult
	}

	ret := compareRpmVersions(v.version, v2.version)
	if ret != 0 {
		return ret
	}

	return compareRpmVersions(v.release, v2.release)
}

// Epoch comparison, standard int comparison for sorting
func compareEpochs(e1 int, e2 int) int {
	if e1 > e2 {
		return 1
	} else if e1 < e2 {
		return -1
	} else {
		return 0
	}
}

func (v rpmVersion) String() string {
	version := ""
	if v.epoch > 0 {
		version += fmt.Sprintf("%d:", v.epoch)
	}
	version += v.version

	if v.release != "" {
		version += fmt.Sprintf("-%s", v.release)
	}
	return version
}

// compareRpmVersions compares two version or release strings without the epoch.
// Source: https://github.com/cavaliercoder/go-rpm/blob/master/version.go
//
// For the original C implementation, see:
// https://github.com/rpm-software-management/rpm/blob/master/lib/rpmvercmp.c#L16
var alphanumPattern = regexp.MustCompile("([a-zA-Z]+)|([0-9]+)|(~)")

// nolint:funlen,gocognit
func compareRpmVersions(a, b string) int {
	// shortcut for equality
	if a == b {
		return 0
	}

	// get alpha/numeric segments
	segsa := alphanumPattern.FindAllString(a, -1)
	segsb := alphanumPattern.FindAllString(b, -1)
	segs := int(math.Min(float64(len(segsa)), float64(len(segsb))))

	// compare each segment
	for i := 0; i < segs; i++ {
		a := segsa[i]
		b := segsb[i]

		// compare tildes
		if []rune(a)[0] == '~' || []rune(b)[0] == '~' {
			if []rune(a)[0] != '~' {
				return 1
			}
			if []rune(b)[0] != '~' {
				return -1
			}
		}

		if unicode.IsNumber([]rune(a)[0]) {
			// numbers are always greater than alphas
			if !unicode.IsNumber([]rune(b)[0]) {
				// a is numeric, b is alpha
				return 1
			}

			// trim leading zeros
			a = strings.TrimLeft(a, "0")
			b = strings.TrimLeft(b, "0")

			// longest string wins without further comparison
			if len(a) > len(b) {
				return 1
			} else if len(b) > len(a) {
				return -1
			}
		} else if unicode.IsNumber([]rune(b)[0]) {
			// a is alpha, b is numeric
			return -1
		}

		// string compare
		if a < b {
			return -1
		} else if a > b {
			return 1
		}
	}

	// segments were all the same but separators must have been different
	if len(segsa) == len(segsb) {
		return 0
	}

	// If there is a tilde in a segment past the min number of segments, find it.
	if len(segsa) > segs && []rune(segsa[segs])[0] == '~' {
		return -1
	} else if len(segsb) > segs && []rune(segsb[segs])[0] == '~' {
		return 1
	}

	// whoever has the most segments wins
	if len(segsa) > len(segsb) {
		return 1
	}
	return -1
}
