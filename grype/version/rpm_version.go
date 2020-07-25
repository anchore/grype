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
	epoch   *int
	version string
	release string
}

func newRpmVersion(raw string) (rpmVersion, error) {
	fields := strings.SplitN(raw, ":", 2)

	var epoch *int
	var remaining = raw
	if len(fields) > 1 {
		// there is an epoch
		epochStr := strings.TrimLeft(fields[0], " ")
		epochInt, err := strconv.Atoi(epochStr)
		if err != nil {
			return rpmVersion{}, fmt.Errorf("unable to parse epoch (%s): %w", epochStr, err)
		}
		epoch = &epochInt
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
func (v rpmVersion) compare(v2 rpmVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}

	// ignore the epoch if either is missing an epoch
	if v.epoch != nil && v2.epoch != nil {
		if *v.epoch > *v2.epoch {
			return 1
		} else if *v.epoch < *v2.epoch {
			return -1
		}
	}

	ret := compareRpmVersions(v.version, v2.version)
	if ret != 0 {
		return ret
	}

	return compareRpmVersions(v.release, v2.release)
}

func (v rpmVersion) String() string {
	version := ""
	if v.epoch == nil {
		version += "none:"
	} else if *v.epoch > 0 {
		version += fmt.Sprintf("%d:", *v.epoch)
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
