package version

import (
	"fmt"
	"strings"
)

var _ Comparator = (*opamVersion)(nil)

// opamVersion is a version of an opam (OCaml) package, ordered like opam does
// (see https://opam.ocaml.org/doc/Manual.html#Version-ordering), which is
// based on the Debian version ordering: versions are compared as alternating
// non-digit and digit parts; non-digit parts character by character, where "~"
// sorts before anything (even the end of the string) and letters sort before
// other characters, and digit parts numerically. For example
// "1.0~beta" < "1.0" < "1.0.0" < "1.0.1".
//
// This is a port of OpamVersionCompare.compare
// (https://github.com/ocaml/opam/blob/master/src/core/opamVersionCompare.ml).
type opamVersion struct {
	raw string
}

func newOpamVersion(raw string) (opamVersion, error) {
	if raw == "" {
		return opamVersion{}, invalidFormatError(OpamFormat, raw, fmt.Errorf("empty version"))
	}
	if i := strings.IndexFunc(raw, func(r rune) bool { return !isOpamVersionChar(r) }); i >= 0 {
		return opamVersion{}, invalidFormatError(OpamFormat, raw, fmt.Errorf("invalid character %q", raw[i]))
	}
	return opamVersion{raw: raw}, nil
}

// isOpamVersionChar reports whether r may appear in an opam version (see the
// "version" production in https://opam.ocaml.org/doc/Manual.html#General-syntax).
func isOpamVersionChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("-+.~_", r)
}

func (v opamVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newOpamVersion(other.Raw)
	if err != nil {
		return 0, err
	}

	return compareOpamVersions(v.raw, o.raw), nil
}

// compareOpamVersions returns -1, 0, or 1 if x is smaller, equal, or larger
// than y. Like opam, the parts before the last "-" are compared first, and the
// parts after it only if those are equal.
func compareOpamVersions(x, y string) int {
	if x == y {
		return 0
	}
	rx, ry := lastDashOrLen(x), lastDashOrLen(y)
	if c := opamLoopLexical(x[:rx], y[:ry]); c != 0 {
		return c
	}
	return opamLoopLexical(x[min(rx+1, len(x)):], y[min(ry+1, len(y)):])
}

func lastDashOrLen(s string) int {
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return i
	}
	return len(s)
}

// opamLoopLexical compares x and y alternating between lexical comparison of
// non-digit parts and numerical comparison of digit parts.
func opamLoopLexical(x, y string) int {
	xi, yi := 0, 0
	for {
		switch {
		case xi == len(x) && yi == len(y):
			return 0
		case xi == len(x):
			return -opamCompareRest(y, yi)
		case yi == len(y):
			return opamCompareRest(x, xi)
		}

		xDigit, yDigit := opamIsDigit(x[xi]), opamIsDigit(y[yi])
		switch {
		case xDigit && yDigit:
			var c int
			if c, xi, yi = opamCompareNumbers(x, y, xi, yi); c != 0 {
				return c
			}
		case xDigit:
			// "~" is smaller than any digit part, anything else is larger
			if y[yi] == '~' {
				return 1
			}
			return -1
		case yDigit:
			if x[xi] == '~' {
				return -1
			}
			return 1
		default:
			if c := opamCompareChars(x[xi], y[yi]); c != 0 {
				return c
			}
			xi, yi = xi+1, yi+1
		}
	}
}

// opamCompareRest compares the rest of s (from i) with the end of a version:
// it is larger, unless it only has zeros left (equal) or continues with "~"
// (smaller).
func opamCompareRest(s string, i int) int {
	i = opamSkipZeros(s, i)
	switch {
	case i == len(s):
		return 0
	case s[i] == '~':
		return -1
	}
	return 1
}

// opamCompareNumbers compares the digit parts of x and y starting at xi and
// yi: after skipping leading zeros, the longer number is larger; numbers of
// the same length are compared digit by digit. It returns the result and the
// indices after the digit parts.
func opamCompareNumbers(x, y string, xi, yi int) (int, int, int) {
	xi, yi = opamSkipZeros(x, xi), opamSkipZeros(y, yi)
	xn, yn := opamSkipDigits(x, xi), opamSkipDigits(y, yi)
	if c := opamCompareInts(xn-xi, yn-yi); c != 0 {
		return c, xn, yn
	}
	for ; yi < yn; xi, yi = xi+1, yi+1 {
		if c := opamCompareInts(int(x[xi]), int(y[yi])); c != 0 {
			return c, xn, yn
		}
	}
	return 0, xn, yn
}

// opamCompareChars orders "~" first, then letters, then anything else (by ASCII).
func opamCompareChars(a, b byte) int {
	rank := func(c byte) int {
		switch {
		case c == '~':
			return 0
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			return 1
		}
		return 2
	}
	if c := opamCompareInts(rank(a), rank(b)); c != 0 {
		return c
	}
	return opamCompareInts(int(a), int(b))
}

func opamSkipZeros(s string, i int) int {
	for i < len(s) && s[i] == '0' {
		i++
	}
	return i
}

func opamSkipDigits(s string, i int) int {
	for i < len(s) && opamIsDigit(s[i]) {
		i++
	}
	return i
}

func opamIsDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func opamCompareInts(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
