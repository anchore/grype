package version

import (
	"fmt"
	"reflect"
	"strings"
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

	// like alpm_pkg_vercmp, the release is only compared when both versions have one
	if v.release == "" || v2.release == "" {
		return 0
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
// It is a port of rpmvercmp() from libalpm (lib/libalpm/version.c in pacman), which differs
// from rpm's algorithm in ways that change the result:
//   - a version that only differs by trailing letters is older ("1.0rc1" < "1.0", "1.5b" < "1.5")
//   - longer runs of separators win ("2___a" > "2_a", "2.0a" < "2.0.a")
//   - "~" and "^" have no special meaning, and trailing zero segments are not ignored
func comparePacmanVersions(a, b string) int {
	// shortcut for equality
	if a == b {
		return 0
	}

	// one and two walk a and b; sep1 and sep2 mark where the current separator run started
	one, two := 0, 0
	for one < len(a) && two < len(b) {
		sep1, sep2 := one, two
		for one < len(a) && !isASCIIAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isASCIIAlnum(b[two]) {
			two++
		}

		// if we ran to the end of either, we are finished with the loop
		if one == len(a) || two == len(b) {
			break
		}

		// if the separator lengths were different, we are also finished
		if one-sep1 != two-sep2 {
			if one-sep1 < two-sep2 {
				return -1
			}
			return 1
		}

		// grab the next completely numeric or completely alpha segment from both
		isNum := isASCIIDigit(a[one])
		end1, end2 := one, two
		if isNum {
			for end1 < len(a) && isASCIIDigit(a[end1]) {
				end1++
			}
			for end2 < len(b) && isASCIIDigit(b[end2]) {
				end2++
			}
		} else {
			for end1 < len(a) && isASCIIAlpha(a[end1]) {
				end1++
			}
			for end2 < len(b) && isASCIIAlpha(b[end2]) {
				end2++
			}
		}

		// the segments are of different types: numeric segments are newer than alpha segments
		if end2 == two {
			if isNum {
				return 1
			}
			return -1
		}

		seg1, seg2 := a[one:end1], b[two:end2]
		if isNum {
			// compare numbers by length first, so long digit runs cannot overflow
			seg1 = strings.TrimLeft(seg1, "0")
			seg2 = strings.TrimLeft(seg2, "0")
			if len(seg1) != len(seg2) {
				if len(seg1) > len(seg2) {
					return 1
				}
				return -1
			}
		}
		if cmp := strings.Compare(seg1, seg2); cmp != 0 {
			return cmp
		}

		one, two = end1, end2
	}

	// all segments compared equal, only the separators were different
	if one == len(a) && two == len(b) {
		return 0
	}

	// libalpm's "final showdown": if all common segments are equal and one version still has
	// characters remaining, the version with more characters wins — unless those characters
	// start with a letter, in which case that version is older. This is how pacman distinguishes
	// "1.0rc" (trailing alpha → older) from "1.0.1" (trailing digit → newer).
	var leftover string
	var sign int
	if one < len(a) {
		leftover = a[one:]
		sign = 1
	} else {
		leftover = b[two:]
		sign = -1
	}

	// skip leading separators
	i := 0
	for i < len(leftover) && !isASCIIAlnum(leftover[i]) {
		i++
	}

	if i < len(leftover) && isASCIIAlpha(leftover[i]) {
		// trailing alpha segment → that side is older
		return -sign
	}
	// trailing numeric segment (or only separators) → that side is newer
	return sign
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isASCIIAlnum(c byte) bool {
	return isASCIIDigit(c) || isASCIIAlpha(c)
}
