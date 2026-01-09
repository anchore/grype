package version

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

var _ Comparator = (*pacmanVersion)(nil)

type pacmanVersion struct {
	epoch   *int
	version string
	release string
}

func newPacmanVersion(raw string) (pacmanVersion, error) {
	epoch, remainingVersion, err := splitEpochFromVersion(raw)
	if err != nil {
		return pacmanVersion{}, err
	}

	fields := strings.SplitN(remainingVersion, "-", 2)
	version := fields[0]

	var release string
	if len(fields) > 1 {
		// there is a release
		release = fields[1]
	}

	return pacmanVersion{
		epoch:   epoch,
		version: version,
		release: release,
	}, nil
}

func (v pacmanVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newPacmanVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	return v.compare(o), nil
}

// Compare returns 0 if v == v2, -1 if v < v2, and +1 if v > v2.
// Pacman uses a similar scheme to RPM: epoch:version-release
// If epochs are NOT present and explicit in both versions then they are ignored for the comparison.
func (v pacmanVersion) compare(v2 pacmanVersion) int {
	if reflect.DeepEqual(v, v2) {
		return 0
	}

	// Only compare epochs if both are present and explicit
	if epochIsPresent(v.epoch) && epochIsPresent(v2.epoch) {
		epochResult := compareEpochs(*v.epoch, *v2.epoch)
		if epochResult != 0 {
			return epochResult
		}
	}

	ret := comparePacmanVersions(v.version, v2.version)
	if ret != 0 {
		return ret
	}

	return comparePacmanVersions(v.release, v2.release)
}

func (v pacmanVersion) String() string {
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

// comparePacmanVersions compares two version or release strings without the epoch.
// Pacman version comparison is similar to RPM, comparing alphanumeric segments.
// Source: https://wiki.archlinux.org/title/Pacman/Tips_and_tricks#Version_comparison
// The scheme is based on RPM's algorithm.
//
// Note: dupl lint is suppressed because although pacman's vercmp is based on rpm's vercmp,
// they are not identical and may diverge in the future. We intentionally keep them decoupled.
//
//nolint:funlen,gocognit,dupl
func comparePacmanVersions(a, b string) int {
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
