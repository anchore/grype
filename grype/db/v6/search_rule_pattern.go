package v6

import (
	"regexp"
	"regexp/syntax"
	"strings"
)

// patternShape is what an anchored rule pattern requires of its subject, derived from the pattern's
// syntax tree. Anchoring is what makes this sound: `^(?:...)$` describes the whole subject, so a
// pattern that is only a literal matches exactly that string, one beginning with a literal constrains
// the subject's prefix, and any literal in its top-level concatenation must appear somewhere in the
// subject. An unanchored pattern would support none of these claims — a literal inside it says nothing
// about the subject, only about the fragment the pattern happened to match.
//
// Each field is a strictly weaker claim than the one above it, and at most one is set. An empty shape
// means nothing could be derived and the regex always runs.
type patternShape struct {
	// exact is the one string the pattern matches, so a comparison replaces the regex outright
	exact string

	// prefix must begin any matching subject
	prefix string

	// needle must appear somewhere in any matching subject
	needle string
}

// possible reports whether the subject could match the pattern this shape came from. It is a
// necessary condition, never a sufficient one: false means the regex cannot match and can be skipped,
// true means it still has to run (except for an exact shape, which is decisive on its own).
func (s patternShape) possible(subject string) bool {
	switch {
	case s.exact != "":
		return subject == s.exact
	case s.prefix != "":
		return strings.HasPrefix(subject, s.prefix)
	case s.needle != "":
		return strings.Contains(subject, s.needle)
	}
	return true
}

// isExact reports whether the shape decides a match by itself, which is what lets rules keyed on an
// exact package name be looked up rather than scanned (see ruleBucket).
func (s patternShape) isExact() bool {
	return s.exact != ""
}

// newPatternShape derives the shape of an already-anchored pattern (the form anchorPattern produces).
// Note that regexp.Regexp.LiteralPrefix is deliberately not used here: its contract is about where a
// *match* begins rather than where the *subject* begins, so it says nothing for an unanchored
// pattern, and what it returns depends on whether the pattern compiled to a one-pass program.
func newPatternShape(anchored string) patternShape {
	re, err := syntax.Parse(anchored, syntax.Perl)
	if err != nil {
		return patternShape{}
	}

	body, ok := anchoredBody(re)
	if !ok {
		// not the shape anchorPattern produces; claim nothing rather than guess
		return patternShape{}
	}

	return shapeOfBody(body)
}

// anchoredBody strips the leading and trailing anchors from a parsed `^(?:...)$`, returning the
// elements between them. A non-capturing group leaves no node of its own, so the tree is always a
// concatenation bracketed by the two anchors.
func anchoredBody(re *syntax.Regexp) ([]*syntax.Regexp, bool) {
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 {
		return nil, false
	}
	first, last := re.Sub[0], re.Sub[len(re.Sub)-1]
	if first.Op != syntax.OpBeginText || last.Op != syntax.OpEndText {
		return nil, false
	}
	return re.Sub[1 : len(re.Sub)-1], true
}

func shapeOfBody(body []*syntax.Regexp) patternShape {
	// a body that is a single node may be an exact literal, or an alternation whose branches are
	// each their own body
	if len(body) == 1 {
		switch body[0].Op {
		case syntax.OpLiteral:
			if lit, ok := plainLiteral(body[0]); ok {
				return patternShape{exact: lit}
			}
			return patternShape{}
		case syntax.OpCapture:
			return shapeOfBody(body[0].Sub)
		case syntax.OpConcat:
			return shapeOfBody(body[0].Sub)
		case syntax.OpAlternate:
			return shapeOfAlternation(body[0].Sub)
		}
		return patternShape{}
	}

	// the body is a concatenation: every element must match, so a literal leading it constrains the
	// subject's prefix and any literal within it must appear somewhere in the subject
	if lit, ok := plainLiteral(body[0]); ok {
		return patternShape{prefix: lit}
	}

	var longest string
	for _, sub := range body {
		if lit, ok := plainLiteral(sub); ok && len(lit) > len(longest) {
			longest = lit
		}
	}
	if longest == "" {
		return patternShape{}
	}
	return patternShape{needle: longest}
}

// shapeOfAlternation keeps only what every branch agrees on: a claim that holds for one branch but not
// another would reject subjects the pattern matches.
func shapeOfAlternation(branches []*syntax.Regexp) patternShape {
	if len(branches) == 0 {
		return patternShape{}
	}

	first := shapeOfBody(branches[:1])
	for _, branch := range branches[1:] {
		if shapeOfBody([]*syntax.Regexp{branch}) != first {
			return patternShape{}
		}
	}
	return first
}

// plainLiteral returns the node's literal text, if it is a literal that a plain string comparison can
// stand in for. Case-insensitive literals are rejected: matching them would need a case-folding
// comparison, which is not the cheap check this exists to provide.
func plainLiteral(re *syntax.Regexp) (string, bool) {
	if re == nil {
		return "", false
	}
	switch re.Op {
	case syntax.OpLiteral:
		if re.Flags&syntax.FoldCase != 0 {
			return "", false
		}
		return string(re.Rune), true
	case syntax.OpCapture:
		return plainLiteral(re.Sub[0])
	}
	return "", false
}

// matchPattern reports whether re matches subject, skipping the regex when the subject fails the
// pattern's shape. The shape is derived from the pattern itself, so this can only skip work the regex
// would have rejected anyway.
//
// This matters more for anchored patterns than it would for unanchored ones: a leading `.*` defeats
// the regexp engine's own literal-prefix scan, leaving it to walk the whole subject before failing.
func matchPattern(re *regexp.Regexp, shape patternShape, subject string) bool {
	if !shape.possible(subject) {
		return false
	}
	if shape.isExact() {
		// possible() already compared the whole subject against the only string that matches
		return true
	}
	return re.MatchString(subject)
}
