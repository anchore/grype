package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var _ Comparator = (*cpanVersion)(nil)

// cpanVersionMax mirrors VERSION_MAX from perl's vutil.h. perl clamps oversized components
// instead of failing, which means two absurdly large but distinct versions compare equal.
// that matches upstream on purpose, it is not a bug to fix.
const cpanVersionMax int64 = 0x7FFFFFFF

// cpanLaxRegexp is $LAX from perl's lib/version/regex.pm (shipped in the CPAN "version"
// distribution), anchored. In regex.pm terms the alternatives are, in order:
//
//	$LAX_DOTTED_DECIMAL_VERSION = v INT (DOTTED+ ALPHA?)?  |  INT? DOTTED{2,} ALPHA?
//	$LAX_DECIMAL_VERSION        = INT (FRACTION | \.)? ALPHA?  |  FRACTION ALPHA?
//
// lax deliberately allows leading zeros, a leading or trailing decimal point, and more than
// three dotted components. The literal string "undef" is also a valid lax version and is
// handled separately below.
//
// Two deviations from regex.pm, both to follow prescan_version, which is what actually
// parses a version and is slightly looser: "v1." is accepted (a trailing "." is only an
// error once a second "." has been seen) and the underscore checks below are tightened.
var cpanLaxRegexp = regexp.MustCompile(
	`^(?:v[0-9]+(?:\.|(?:\.[0-9]+)+(?:_[0-9]+)?)?|[0-9]*(?:\.[0-9]+){2,}(?:_[0-9]+)?|[0-9]+(?:\.[0-9]+|\.)?(?:_[0-9]+)?|\.[0-9]+(?:_[0-9]+)?)$`)

type cpanVersion struct {
	original   string
	components []int64
	// isAlpha records the single-underscore developer-release marker. It is display-only:
	// Perl_vcmp never reads it, so "1.23_01" sorts above "1.23" purely because its
	// underscore digits fold into the numeric groups, not because of any pre-release rule.
	isAlpha bool
}

// newCpanVersion ports Perl_prescan_version and Perl_scan_version from perl's vutil.c, which
// is the same code the CPAN "version" distribution ships and therefore what every CPAN
// toolchain comparison bottoms out in.
func newCpanVersion(raw string) (*cpanVersion, error) {
	// prescan_version treats whitespace as a version terminator, an artifact of scanning
	// versions out of perl source
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("invalid version format (version required)")
	}

	// $LAX admits the literal string "undef", a concession to ExtUtils::MM->parse_version
	// returning undef as a string. perl parses it as version 0.
	if s == "undef" {
		return &cpanVersion{original: raw, components: []int64{0}}, nil
	}

	if !cpanLaxRegexp.MatchString(s) {
		return nil, fmt.Errorf("invalid version format (non-numeric data)")
	}

	// prescan_version rejects two underscore placements that the lax grammar lets through:
	// an underscore with no preceding decimal point ("1_2") and one not directly after a
	// digit ("1._2"). the grammar already caps underscores at one.
	if i := strings.IndexByte(s, '_'); i >= 0 {
		if !strings.Contains(s[:i], ".") {
			return nil, fmt.Errorf("invalid version format (alpha without decimal)")
		}
		if s[i-1] < '0' || s[i-1] > '9' {
			return nil, fmt.Errorf("invalid version format (fractional part required)")
		}
	}

	v := cpanVersion{original: raw, isAlpha: strings.Contains(s, "_")}
	// the underscore is only a marker; its digits belong to the group they sit in, so
	// "1.23_01" scans as "1.2301" and "v1.2_3" as "v1.23"
	s = strings.ReplaceAll(s, "_", "")

	// a leading "v" followed by a digit, or a second "." seen while scanning the fractional
	// part, makes the whole string dotted-decimal. everything else is decimal.
	qv := strings.HasPrefix(s, "v")
	if qv {
		s = s[1:]
	}
	if strings.Count(s, ".") > 1 {
		qv = true
	}

	if qv {
		for _, part := range strings.Split(s, ".") {
			component, overflowed := cpanComponent(part)
			v.components = append(v.components, component)
			if overflowed {
				// scan_version stops consuming once it flags an overflow, so nothing
				// after the clamped component makes it into the vector
				break
			}
		}
		// quoted versions always get at least three terms
		for len(v.components) < 3 {
			v.components = append(v.components, 0)
		}
		return &v, nil
	}

	intPart, fracPart, hasFraction := strings.Cut(s, ".")
	intComponent, overflowed := cpanComponent(intPart)
	v.components = append(v.components, intComponent)
	if overflowed {
		// same stop-on-overflow rule as above: the fractional groups are never reached
		return &v, nil
	}
	if hasFraction {
		// a trailing "." with no digits still contributes one zero component
		if fracPart == "" {
			fracPart = "0"
		}
		// each fractional group takes at most three digits, evaluated with place values
		// 100, 10, 1. a short final group is left-aligned, which is the same as
		// right-padding the fractional digits to a multiple of three.
		for len(fracPart)%3 != 0 {
			fracPart += "0"
		}
		for i := 0; i < len(fracPart); i += 3 {
			component, _ := cpanComponent(fracPart[i : i+3])
			v.components = append(v.components, component)
		}
	}

	return &v, nil
}

// cpanComponent converts one run of digits, clamping at VERSION_MAX the way perl does rather
// than erroring, and reporting whether it had to. An empty run (from a leading ".") is zero.
func cpanComponent(digits string) (value int64, overflowed bool) {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return 0, false
	}
	if len(digits) > 10 {
		return cpanVersionMax, true
	}
	value, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || value > cpanVersionMax {
		return cpanVersionMax, true
	}
	return value, false
}

func (v *cpanVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	o, err := newCpanVersion(other.Raw)
	if err != nil {
		return 0, invalidFormatError(CpanFormat, other.Raw, err)
	}

	return v.compare(o), nil
}

// compare is Perl_vcmp: compare pairwise over the shared prefix, then treat the longer side
// as equal only if every remaining component is zero, so v1.2 == v1.2.0 == v1.2.0.0. The
// alpha flag never participates, and neither does a numified float (numify is lossy on long
// CPAN versions in exactly the cases this comparator exists for).
func (v *cpanVersion) compare(other *cpanVersion) int {
	shared := min(len(v.components), len(other.components))
	for i := range shared {
		switch {
		case v.components[i] < other.components[i]:
			return -1
		case v.components[i] > other.components[i]:
			return 1
		}
	}

	for _, c := range v.components[shared:] {
		if c != 0 {
			return 1
		}
	}
	for _, c := range other.components[shared:] {
		if c != 0 {
			return -1
		}
	}
	return 0
}

func (v *cpanVersion) String() string {
	return v.original
}
