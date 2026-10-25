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
	for i := range minSegs {
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

	// libalpm's final showdown: a remaining alpha segment makes the version it
	// belongs to older, but only when the tail starts with the letters
	// themselves ("2.4.0rc4" sorts below "2.4.0", while "1.5.a" is still newer
	// than "1.5" because its tail starts with a separator). Reference:
	// libalpm's rpmvercmp in lib/libalpm/version.c:
	//
	//	if ( (!*one && !isalpha((int)*two)) || isalpha((int)*one) ) {
	//		ret = -1;
	//	} else {
	//		ret = 1;
	//	}
	if la := pacmanLeftover(a, minSegs); len(segsa) > minSegs && pacmanStartsWithLetter(la) {
		return -1
	}
	if lb := pacmanLeftover(b, minSegs); len(segsb) > minSegs && pacmanStartsWithLetter(lb) {
		return 1
	}

	// whoever has the most segments wins
	if len(segsa) > len(segsb) {
		return 1
	}
	return -1
}

// pacmanLeftover returns the part of raw that begins after the first n
// alphanum segments -- the segment classes of alphanumPattern: letter runs,
// digit runs, and single '~' characters. The result includes any separator
// characters, so callers can tell a tail like "rc4" (letters start
// immediately) from one like ".a" (a separator comes first).
func pacmanLeftover(raw string, n int) string {
	i := 0
	for s := 0; s < n && i < len(raw); s++ {
		// skip the separators before the segment
		for i < len(raw) && !isPacmanSegmentByte(raw[i]) {
			i++
		}
		if i == len(raw) {
			break
		}
		switch c := raw[i]; {
		case c == '~':
			i++
		case c >= '0' && c <= '9':
			for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
				i++
			}
		default:
			for i < len(raw) && isPacmanLetterByte(raw[i]) {
				i++
			}
		}
	}
	return raw[i:]
}

func isPacmanSegmentByte(c byte) bool {
	return c == '~' || (c >= '0' && c <= '9') || isPacmanLetterByte(c)
}

func isPacmanLetterByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// pacmanStartsWithLetter reports whether the leftover tail of a version
// begins with a letter (as opposed to a digit or a separator), which
// libalpm's final showdown uses to make the shorter version the newer one.
func pacmanStartsWithLetter(leftover string) bool {
	return leftover != "" && isPacmanLetterByte(leftover[0])
}
