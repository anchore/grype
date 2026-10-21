package pkg

import (
	"regexp"
	"strings"
)

var goTypeParamPattern = regexp.MustCompile(`\[[^]]*]`)

// normalizeGoSymbol converts a symbol name as found in a binary symbol table into govulndb's symbol
// naming convention so the two can be compared:
//   - pointer-receiver decoration is removed: "pkg.(*T).M" -> "pkg.T.M"
//   - generic instantiations lose their type parameters: "pkg.(*T[go.shape.int]).M" -> "pkg.T.M"
//   - the compiler's "-fm" method-value-wrapper suffix is removed: "pkg.(*T).M-fm" -> "pkg.T.M".
//     A method-value wrapper is emitted when a method is referenced as a value (e.g. passed as a
//     callback), so its presence means the underlying method is used.
//
// Known limitation: the type-parameter regex assumes a single, non-nested bracket group, so a nested
// instantiation is not normalized cleanly. The consequence is a missed match for that symbol, not a
// false positive.
func normalizeGoSymbol(symbol string) string {
	// most symbols carry neither pointer-receiver decoration nor a type-parameter group, so gate the
	// string/regex passes on a cheap byte scan... and paren strips only matter for pointer
	// receivers.
	if strings.IndexByte(symbol, '(') >= 0 {
		symbol = strings.ReplaceAll(symbol, "(*", "")
		symbol = strings.ReplaceAll(symbol, ")", "")
	}
	symbol = strings.TrimSuffix(symbol, "-fm")
	if strings.IndexByte(symbol, '[') >= 0 {
		symbol = goTypeParamPattern.ReplaceAllString(symbol, "")
	}
	return symbol
}

// normalizeGoSymbols returns a fresh symbol table with every local symbol name converted to
// govulndb's naming convention (see normalizeGoSymbol) and de-duplicated per import path. It is
// applied once when a Go binary package is built (golangMetadataFromPkg) so the gosymbols qualifier
// compares already-normalized names and never re-normalizes on the vulnerability-matching hot path.
//
// A fresh map is built rather than mutating the input, which is shared with the syft package that
// produced it. An import path present with an empty local list is preserved (it is load-bearing:
// the qualifier treats such a path as present for whole-package advisories).
func normalizeGoSymbols(raw map[string][]string) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string][]string, len(raw))
	for path, locals := range raw {
		seen := make(map[string]struct{}, len(locals))
		normalized := make([]string, 0, len(locals))
		for _, local := range locals {
			n := normalizeGoSymbol(local)
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			normalized = append(normalized, n)
		}
		out[path] = normalized
	}
	return out
}
