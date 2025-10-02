package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	hashiVer "github.com/anchore/go-version"
)

// derived from https://semver.org/, but additionally matches:
// - partial versions (e.g. "2.0")
// - optional prefix "v" (e.g. "v1.0.0")
var pseudoSemverPattern = regexp.MustCompile(`^v?(0|[1-9]\d*)(\.(0|[1-9]\d*))?(\.(0|[1-9]\d*))?(?:(-|alpha|beta|rc)((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

type fuzzyConstraint struct {
	RawPhrase          string
	PhraseHint         string
	SemanticConstraint *hashiVer.Constraints
	Constraints        simpleRangeExpression
}

func newFuzzyConstraint(phrase, hint string) (fuzzyConstraint, error) {
	if phrase == "" {
		// an empty constraint is always satisfied
		return fuzzyConstraint{
			RawPhrase:  phrase,
			PhraseHint: hint,
		}, nil
	}

	constraints, err := parseRangeExpression(phrase)
	if err != nil {
		return fuzzyConstraint{}, fmt.Errorf("could not create fuzzy constraint: %+v", err)
	}
	var semverConstraint *hashiVer.Constraints

	// check all version unit phrases to see if this is a valid semver constraint
	valid := true
check:
	for _, units := range constraints.Units {
		for _, unit := range units {
			if !pseudoSemverPattern.MatchString(unit.Version) {
				valid = false
				break check
			}
		}
	}

	if value, err := hashiVer.NewConstraint(phrase); err == nil && valid {
		semverConstraint = &value
	}

	return fuzzyConstraint{
		RawPhrase:          phrase,
		PhraseHint:         hint,
		Constraints:        constraints,
		SemanticConstraint: semverConstraint,
	}, nil
}

func (f fuzzyConstraint) Satisfied(verObj *Version) (bool, error) {
	if f.RawPhrase == "" && verObj != nil {
		// an empty constraint is always satisfied
		return true, nil
	} else if verObj == nil {
		if f.RawPhrase != "" {
			// a non-empty constraint with no version given should always fail
			return false, nil
		}
		return true, nil
	}

	version := verObj.Raw

	// rebuild temp constraint based off of ver obj
	if verObj.Format != UnknownFormat {
		newConstraint, err := GetConstraint(f.RawPhrase, verObj.Format)
		// check if constraint is not fuzzyConstraint
		_, ok := newConstraint.(fuzzyConstraint)
		if err == nil && !ok {
			satisfied, err := newConstraint.Satisfied(verObj)
			if err == nil {
				return satisfied, nil
			}
		}
	}

	// attempt semver first, then fallback to fuzzy part matching...
	if f.SemanticConstraint != nil {
		if pseudoSemverPattern.MatchString(version) {
			// we're stricter about accepting looser semver rules here since we have no context about
			// the true format of the version, thus we want to reduce the change of false negatives
			if semver, err := newSemanticVersion(version, true); err == nil {
				return f.SemanticConstraint.Check(semver.obj), nil
			}
		}
	}
	// semver didn't work, use fuzzy part matching instead...
	return f.Constraints.satisfied(UnknownFormat, verObj)
}

func (f fuzzyConstraint) Format() Format {
	return UnknownFormat
}

func (f fuzzyConstraint) String() string {
	if f.RawPhrase == "" {
		return "none (unknown)"
	}
	if f.PhraseHint != "" {
		return fmt.Sprintf("%s (%s)", f.RawPhrase, f.PhraseHint)
	}
	return fmt.Sprintf("%s (unknown)", f.RawPhrase)
}

func (f fuzzyConstraint) Value() string {
	return f.RawPhrase
}

// Note: the below code is from https://github.com/facebookincubator/nvdtools/blob/688794c4d3a41929eeca89304e198578d4595d53/cvefeed/nvd/smartvercmp.go (apache V2)
// I'd prefer to import this functionality instead of copying it, however, these functions are not exported from the package

// fuzzyVersionComparison compares stringified versions of software.
// It tries to do the right thing for any unspecified version type,
// assuming v1 and v2 have the same version convention.
// It will return meaningful result for "95SE" vs "98SP1" or for "16.3.2" vs. "3.7.0",
// but not for "2000" vs "11.7".
// Returns -1 if v1 < v2, 1 if v1 > v2 and 0 if v1 == v2.
func fuzzyVersionComparison(v1, v2 string) int {
	v1 = stripLeadingV(v1)
	v2 = stripLeadingV(v2)
	for s1, s2 := v1, v2; len(s1) > 0 && len(s2) > 0; {
		num1, cmpTo1, skip1 := parseVersionParts(s1)
		num2, cmpTo2, skip2 := parseVersionParts(s2)

		ns1 := s1[:cmpTo1]
		ns2 := s2[:cmpTo2]
		diff := num1 - num2
		switch {
		case diff > 0: // ns1 has longer numeric part
			ns2 = leftPad(ns2, diff)
		case diff < 0: // ns2 has longer numeric part
			ns1 = leftPad(ns1, -diff)
		}

		// Check if both parts look like they have patch numbers (e.g., "p9" vs "p15")
		if hasPatchNumber(ns1) && hasPatchNumber(ns2) {
			if cmp := comparePatchNumbers(ns1, ns2); cmp != 0 {
				return cmp
			}
		} else if cmp := strings.Compare(ns1, ns2); cmp != 0 {
			return cmp
		}

		s1 = s1[skip1:]
		s2 = s2[skip2:]
	}
	// everything is equal so far, the longest wins
	if len(v1) > len(v2) {
		return 1
	}
	if len(v2) > len(v1) {
		return -1
	}
	return 0
}

// parseVersionParts returns the length of consecutive run of digits in the beginning of the string,
// the last non-separator character (which should be compared), and index at which the version part (major, minor etc.) ends,
// i.e. the position of the dot or end of the line.
// E.g. parseVersionParts("11.b4.16-New_Year_Edition") will return (2, 3, 4)
func parseVersionParts(v string) (int, int, int) {
	var num int
	for num = 0; num < len(v); num++ {
		if v[num] < '0' || v[num] > '9' {
			break
		}
	}
	if num == len(v) {
		return num, num, num
	}
	// Any punctuation separates the parts.
	skip := strings.IndexFunc(v, func(b rune) bool {
		// !"#$%&'()*+,-./ are dec 33 to 47, :;<=>?@ are dec 58 to 64, [\]^_` are dec 91 to 96 and {|}~ are dec 123 to 126.
		// So, punctuation is in dec 33-126 range except 48-57, 65-90 and 97-122 gaps.
		// This inverse logic allows for early short-circuiting for most of the chars and shaves ~20ns in benchmarks.
		// linters might yell about De Morgan's law here - we ignore them in this case
		//nolint:staticcheck
		return b >= '!' && b <= '~' &&
			!(b > '/' && b < ':' ||
				b > '@' && b < '[' ||
				b > '`' && b < '{')
	})
	if skip == -1 {
		return num, len(v), len(v)
	}
	return num, skip, skip + 1
}

// leftPad pads s with n '0's
func leftPad(s string, n int) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte('0')
	}
	sb.WriteString(s)
	return sb.String()
}

func stripLeadingV(ver string) string {
	return strings.TrimPrefix(ver, "v")
}

// hasPatchNumber returns true if the version segment looks like it has a patch number
// e.g., "p9", "p15", "rc1", "alpha2", "8p9", "8p15"
func hasPatchNumber(segment string) bool {
	for i, r := range segment {
		if unicode.IsLetter(r) && i < len(segment)-1 {
			next := rune(segment[i+1])
			if unicode.IsDigit(next) {
				return true
			}
		}
	}
	return false
}

// comparePatchNumbers compares version segments with patch numbers numerically
// e.g., "p9" < "p15", "rc1" < "rc10", "8p9" < "8p15"
func comparePatchNumbers(left, right string) int {
	findLetterDigitBoundary := func(s string) int {
		for i, r := range s {
			if unicode.IsLetter(r) && i < len(s)-1 && unicode.IsDigit(rune(s[i+1])) {
				return i + 1
			}
		}
		return -1
	}

	leftPos := findLetterDigitBoundary(left)
	rightPos := findLetterDigitBoundary(right)

	if leftPos > 0 && rightPos > 0 {
		leftPrefix, leftNumStr := left[:leftPos], left[leftPos:]
		rightPrefix, rightNumStr := right[:rightPos], right[rightPos:]

		if cmp := strings.Compare(leftPrefix, rightPrefix); cmp != 0 {
			return cmp
		}

		if leftNum, err1 := strconv.Atoi(leftNumStr); err1 == nil {
			if rightNum, err2 := strconv.Atoi(rightNumStr); err2 == nil {
				if leftNum < rightNum {
					return -1
				} else if leftNum > rightNum {
					return 1
				}
			}
		}
	}

	return strings.Compare(left, right)
}
