package version

import (
	"errors"
	"strings"
)

var _ Comparator = (*apkVersion)(nil)

// errInvalidApkVersion keeps the historical "invalid version" cause in apk
// parse errors, which callers and tests match on.
var errInvalidApkVersion = errors.New("invalid version")

// apkPreSuffixes and apkPostSuffixes are the version suffixes apk orders
// before (_alpha, _beta, _pre, _rc) and after (_cvs, _svn, _git, _hg, _p) an
// unsuffixed release, in the order apk sorts them.
var (
	apkPreSuffixes  = [4]string{"alpha", "beta", "pre", "rc"}
	apkPostSuffixes = [5]string{"cvs", "svn", "git", "hg", "p"}
)

// apkVersion compares Alpine package versions with the same ordering as
// apk-tools >= 2.14.0 (the "apk version -t" behavior).
//
// The previously used port of the apk ordering (knqyf263/go-apk-version)
// stops at apk-tools 2.10. Its tokenizer swallows every zero of a numeric
// component that is just zeros, so a version like "1.0" never emits its zero
// digit and any pre-release suffix that follows compares above the release:
// "1.0_rc1" > "1.0". For a vulnerability fixed in "1.0", a package at
// "1.0_rc1" then satisfies "installed >= fixed" and the match is hidden
// (#3800). apk-tools fixed this in commit 3df4a948 (released in v2.14.0) by
// keeping the final zero of the run as a regular digit token.
//
// Ordering reference: the apk version format description and the upstream
// test vector table (apk-tools src/version.c and test/version.data).
type apkVersion struct {
	raw string
}

func newApkVersion(raw string) (apkVersion, error) {
	trimmed := trimLeadingV(raw)
	if !validApkVersion(trimmed) {
		return apkVersion{}, invalidFormatError(ApkFormat, raw, errInvalidApkVersion)
	}
	return apkVersion{raw: trimmed}, nil
}

// trimLeadingV removes a single leading 'v' or 'V' prefix only if it's followed by a digit.
// This allows versions like "v1.5.0" to be treated as "1.5.0" while preserving other strings as-is.
func trimLeadingV(raw string) string {
	if len(raw) >= 2 && (raw[0] == 'v' || raw[0] == 'V') && raw[1] >= '0' && raw[1] <= '9' {
		return raw[1:]
	}
	return raw
}

func (v apkVersion) Compare(other *Version) (int, error) {
	if other == nil {
		return -1, ErrNoVersionProvided
	}

	otherApk, err := newApkVersion(other.Raw)
	if err != nil {
		return -1, err
	}

	return compareApkVersions(v.raw, otherApk.raw), nil
}

// apkTokenKind is the state a parsed token leaves the parser in. The kind
// attached to a token is the state the parser moves to for the next token,
// which is what makes comparing two versions token-kind by token-kind well
// defined. The constant order mirrors the apk token ranks: an invalid token
// sorts lowest, the end of a version highest.
type apkTokenKind int

const (
	apkTokenInvalid apkTokenKind = iota - 1
	apkTokenDigitOrZero
	apkTokenDigit
	apkTokenLetter
	apkTokenSuffix
	apkTokenSuffixNo
	apkTokenRevisionNo
	apkTokenEnd
)

type apkVersionParser struct {
	raw string
	i   int
}

// nextToken consumes the separator at the current position, if any, and
// returns the state that follows the given one: "." starts another numeric
// component, "_" starts a suffix and "-r" a revision. A lowercase letter may
// follow a numeric component, and digits may follow either a letter or a
// suffix name.
func (p *apkVersionParser) nextToken(kind apkTokenKind) apkTokenKind {
	next := apkTokenInvalid

	switch {
	case p.i >= len(p.raw):
		next = apkTokenEnd
	case (kind == apkTokenDigit || kind == apkTokenDigitOrZero) && isApkLower(p.raw[p.i]):
		next = apkTokenLetter
	case kind == apkTokenLetter && isApkDigit(p.raw[p.i]):
		next = apkTokenDigit
	case kind == apkTokenSuffix && isApkDigit(p.raw[p.i]):
		next = apkTokenSuffixNo
	default:
		switch p.raw[p.i] {
		case '.':
			next = apkTokenDigitOrZero
		case '_':
			next = apkTokenSuffix
		case '-':
			if p.i+1 < len(p.raw) && p.raw[p.i+1] == 'r' {
				next = apkTokenRevisionNo
				p.i++ // consume the "r"; the "-" is consumed below
			} else {
				next = apkTokenInvalid
			}
		}
		p.i++
	}

	// a version may only continue with a state at or above the current one,
	// with the three legal step-downs apk allows
	if next < kind &&
		!(next == apkTokenDigitOrZero && kind == apkTokenDigit) &&
		!(next == apkTokenSuffix && kind == apkTokenSuffixNo) &&
		!(next == apkTokenDigit && kind == apkTokenLetter) {
		next = apkTokenInvalid
	}

	return next
}

// getToken reads the token expected in the given state and returns its value
// together with the state the parser is in afterwards.
func (p *apkVersionParser) getToken(kind apkTokenKind) (int64, apkTokenKind) {
	if p.i >= len(p.raw) {
		return 0, apkTokenEnd
	}

	switch kind {
	case apkTokenDigitOrZero:
		// A numeric component starting with zero sorts by the length of its
		// zero run: every zero past the first counts as -1, and the final
		// zero is left in the stream to be read as a regular digit. This is
		// the behavior apk-tools fixed in 3df4a948 (v2.14.0); without it a
		// "X.0" version never emits its zero digit and a pre-release suffix
		// that follows compares above the release.
		if p.raw[p.i] == '0' {
			zeros := 0
			for p.i+zeros+1 < len(p.raw) && p.raw[p.i+zeros+1] == '0' {
				zeros++
			}
			p.i += zeros
			return int64(-zeros), p.after(kind, apkTokenDigit)
		}
		return p.number(kind)
	case apkTokenDigit, apkTokenSuffixNo, apkTokenRevisionNo:
		return p.number(kind)
	case apkTokenLetter:
		value := int64(p.raw[p.i])
		p.i++
		return value, p.after(kind, apkTokenInvalid)
	case apkTokenSuffix:
		return p.suffix()
	default:
		return -1, apkTokenInvalid
	}
}

// number reads a run of digits as a single value. apk bounds the value by
// rejecting digit runs of 18 or more characters.
func (p *apkVersionParser) number(kind apkTokenKind) (int64, apkTokenKind) {
	start := p.i
	var value int64
	for p.i < len(p.raw) && isApkDigit(p.raw[p.i]) {
		value = value*10 + int64(p.raw[p.i]-'0')
		p.i++
	}
	if p.i-start >= 18 {
		return -1, apkTokenInvalid
	}
	return value, p.after(kind, apkTokenInvalid)
}

// suffix reads a pre- or post-release suffix name. Pre-release suffixes get
// negative values so they sort below a release without a suffix.
func (p *apkVersionParser) suffix() (int64, apkTokenKind) {
	for idx, name := range apkPreSuffixes {
		if strings.HasPrefix(p.raw[p.i:], name) {
			p.i += len(name)
			return int64(idx - len(apkPreSuffixes)), p.after(apkTokenSuffix, apkTokenInvalid)
		}
	}
	for idx, name := range apkPostSuffixes {
		if strings.HasPrefix(p.raw[p.i:], name) {
			p.i += len(name)
			return int64(idx), p.after(apkTokenSuffix, apkTokenInvalid)
		}
	}
	// an unknown suffix name makes the whole version invalid
	return -1, apkTokenInvalid
}

// after returns the state after the token just read: the end of the version,
// the state the token itself determined, or whatever separator follows.
func (p *apkVersionParser) after(kind, determined apkTokenKind) apkTokenKind {
	if p.i >= len(p.raw) {
		return apkTokenEnd
	}
	if determined != apkTokenInvalid {
		return determined
	}
	return p.nextToken(kind)
}

func isApkDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isApkLower(c byte) bool {
	return c >= 'a' && c <= 'z'
}

// validApkVersion reports whether the version tokenizes to completion.
func validApkVersion(raw string) bool {
	p := &apkVersionParser{raw: raw}
	kind := apkTokenDigit
	for kind != apkTokenEnd && kind != apkTokenInvalid {
		_, kind = p.getToken(kind)
	}
	return kind == apkTokenEnd
}

// compareApkVersions compares two apk versions the way "apk version -t"
// does: token by token while both sides agree on value and kind, then by
// value, then by the kind of the first differing token -- except that a
// pre-release suffix sorts below the release even though the suffixed version
// still has tokens left.
func compareApkVersions(a, b string) int {
	ap := &apkVersionParser{raw: a}
	bp := &apkVersionParser{raw: b}

	at, bt := apkTokenDigit, apkTokenDigit
	var av, bv int64

	for at == bt && at != apkTokenEnd && at != apkTokenInvalid && av == bv {
		av, at = ap.getToken(at)
		bv, bt = bp.getToken(bt)
	}

	switch {
	case av < bv:
		return -1
	case av > bv:
		return 1
	}

	if at == bt {
		return 0
	}

	// both sides agree so far; a pre-release suffix (_alpha, _beta, _pre,
	// _rc) loses against the release, while anything else that continues
	// the version wins against one that has already ended
	if at == apkTokenSuffix {
		if value, _ := ap.getToken(apkTokenSuffix); value < 0 {
			return -1
		}
	}
	if bt == apkTokenSuffix {
		if value, _ := bp.getToken(apkTokenSuffix); value < 0 {
			return 1
		}
	}

	switch {
	case at > bt:
		return -1
	case bt > at:
		return 1
	}
	return 0
}
