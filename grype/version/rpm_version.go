package version

import (
	"fmt"
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
	epoch, remainingVersion, err := splitEpochFromVersion(raw)
	if err != nil {
		return rpmVersion{}, err
	}

	fields := strings.SplitN(remainingVersion, "-", 2)
	version := fields[0]

	var release string
	if len(fields) > 1 {
		// there is a release
		release = fields[1]
	}

	return rpmVersion{
		epoch:   epoch,
		version: version,
		release: release,
	}, nil
}

func splitEpochFromVersion(rawVersion string) (*int, string, error) {
	fields := strings.SplitN(rawVersion, ":", 2)

	// When the epoch is not included, should be considered to be 0 during
	// comparisons (see https://github.com/rpm-software-management/rpm/issues/450).
	// But, often the inclusion of the epoch in vuln databases or source RPM
	// filenames is not consistent so, represent a missing epoch as nil. This allows
	// the comparison logic itself to determine if it should use a zero or another
	// value which supports more flexible comparison options because the version
	// creation is not lossy

	if len(fields) == 1 {
		return nil, rawVersion, nil
	}

	// there is an epoch
	epochStr := strings.TrimLeft(fields[0], " ")

	epoch, err := strconv.Atoi(epochStr)
	if err != nil {
		return nil, "", fmt.Errorf("unable to parse epoch (%s): %w", epochStr, err)
	}

	return &epoch, fields[1], nil
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
// encountered in vuln scanning. If epochs are NOT present and explicit
// (e.g. >= 0) in both versions then they are ignored for the comparison.
// For a rpm spec-compliant comparison, see strictCompare() instead
func (v rpmVersion) compare(v2 rpmVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}

	// Only compare epochs if both are present and explicit. This is technically
	// against what RedHat says to do with missing epoch (which is to assume a 0 epoch).
	// However, since we may be dealing with upstream data sources where there is an epoch
	// for a package but the value was stripped, the best we can do is to compare only the
	// version values without the epoch values.
	if epochIsPresent(v.epoch) && epochIsPresent(v2.epoch) {
		epochResult := compareEpochs(*v.epoch, *v2.epoch)
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

func epochIsPresent(epoch *int) bool {
	return epoch != nil
}

// Epoch comparison, standard int comparison for sorting
func compareEpochs(e1 int, e2 int) int {
	switch {
	case e1 > e2:
		return 1
	case e1 < e2:
		return -1
	default:
		return 0
	}
}

func (v rpmVersion) String() string {
	version := ""
	if v.epoch != nil {
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

//nolint:funlen,gocognit
func compareRpmVersions(a, b string) int {
	// shortcut for equality
	if a == b {
		return 0
	}

	// get alpha/numeric segments
	segsa := alphanumPattern.FindAllString(a, -1)
	segsb := alphanumPattern.FindAllString(b, -1)
	maxSegs := max(len(segsa), len(segsb))
	minSegs := min(len(segsa), len(segsb))

	// compare each segment
	for i := 0; i < minSegs; i++ {
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
	if len(segsa) > minSegs && []rune(segsa[minSegs])[0] == '~' {
		return -1
	} else if len(segsb) > minSegs && []rune(segsb[minSegs])[0] == '~' {
		return 1
	}
	// are the remaining segments 0s?
	segaAll0s := true
	segbAll0s := true
	for i := minSegs; i < maxSegs; i++ {
		if i < len(segsa) && segsa[i] != "0" {
			segaAll0s = false
		}
		if i < len(segsb) && segsb[i] != "0" {
			segbAll0s = false
		}
	}

	if segaAll0s && segbAll0s {
		return 0
	}

	// whoever has the most segments wins
	if len(segsa) > len(segsb) {
		return 1
	}
	return -1
}
