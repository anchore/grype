package gosymbols

import (
	"sort"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// Import describes a single package within an affected Go module along with the vulnerable
// symbols it contains (mirroring govulndb's `ecosystem_specific.imports` entries).
type Import struct {
	// Path is the import path of the package within the affected module (e.g. "golang.org/x/net/html").
	Path string

	// Symbols lists the vulnerable function/method names within the package (e.g. "Parse" or
	// "Decoder.Decode"). An empty list means the entire package is considered vulnerable.
	Symbols []string
}

type gosymbolsQualifier struct {
	imports []Import
}

func New(imports []Import) qualifier.Qualifier {
	return &gosymbolsQualifier{imports: imports}
}

// Satisfied reports whether the package plausibly uses any of the vulnerable symbols. The check
// only applies when the scanned package carries binary symbol evidence (go binaries cataloged with
// symbol capture enabled); packages without symbol evidence always satisfy the qualifier so that
// module-granularity matching behavior is preserved.
func (q *gosymbolsQualifier) Satisfied(p pkg.Package) (bool, error) {
	matched, scoped := q.evaluate(p)
	if !scoped {
		// no symbol scoping (advisory lists no imports, or the package carries no symbol evidence):
		// preserve module-granularity matching
		return true, nil
	}
	return len(matched) > 0, nil
}

// MatchedSymbols returns the fully-qualified vulnerable Go symbols the package is found to use, for
// the first symbol-scoped qualifier among quals that reports a concrete intersection — sorted and
// de-duplicated. A whole-package (symbol-less) advisory import contributes its import path alone. It
// returns nil when no qualifier carries symbol scoping (module-granularity matching) or the package
// uses none of the vulnerable symbols. It is a package-level function rather than a method behind an
// exported interface so the generic match-detail builder can surface the intersection without
// widening this package's public API.
func MatchedSymbols(quals []qualifier.Qualifier, p pkg.Package) []string {
	for _, q := range quals {
		gq, ok := q.(*gosymbolsQualifier)
		if !ok {
			continue
		}
		if matched, scoped := gq.evaluate(p); scoped && len(matched) > 0 {
			return matched
		}
	}
	return nil
}

// evaluate is the single source of truth for both the filter (Satisfied) and the report
// (MatchedSymbols): it returns the sorted, de-duplicated set of fully-qualified vulnerable symbols
// the package is found to use, plus whether symbol scoping applied at all. scoped is false when the
// advisory references no imports or the package carries no symbol evidence — both fall back to
// module-granularity matching. When scoped is true, a non-empty result means at least one vulnerable
// symbol (or a whole-package import path) is present; empty means the package uses none of them.
func (q *gosymbolsQualifier) evaluate(p pkg.Package) (matched []string, scoped bool) {
	if len(q.imports) == 0 {
		return nil, false
	}

	present, ok := q.present(p)
	if !ok {
		return nil, false
	}

	seen := make(map[string]struct{})
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		matched = append(matched, s)
	}

	for _, imp := range q.imports {
		locals, ok := present[imp.Path]
		if !ok {
			continue
		}
		if len(imp.Symbols) == 0 {
			// whole package vulnerable: the import path is present, so report it
			add(imp.Path)
			continue
		}
		for _, vulnSym := range imp.Symbols {
			if _, ok := locals[vulnSym]; ok {
				add(imp.Path + "." + vulnSym)
			}
		}
	}

	sort.Strings(matched)
	return matched, true
}

// present returns the package's binary symbol evidence, as import path -> set of local symbol names,
// restricted to the import paths this advisory actually references (q.imports), plus whether such
// evidence exists. Symbol names are already normalized to govulndb's convention at provision time
// (see pkg.normalizeGoSymbols), so only lookup happens here. Packages without symbol evidence (not a
// go binary, or cataloged without symbol capture) report ok=false so callers fall back to
// module-granularity matching.
func (q *gosymbolsQualifier) present(p pkg.Package) (map[string]map[string]struct{}, bool) {
	m, ok := p.Metadata.(pkg.GolangBinMetadata)
	if !ok || len(m.Symbols) == 0 {
		return nil, false
	}

	present := make(map[string]map[string]struct{}, len(q.imports))
	for _, imp := range q.imports {
		if _, done := present[imp.Path]; done {
			continue // path already collected (advisory referenced it more than once)
		}
		locals, ok := m.Symbols[imp.Path]
		if !ok {
			continue // import path not present in the binary; leave it absent
		}
		// a path present with an empty local list still yields an (empty) set entry, so the
		// whole-package present check (evaluate) sees the path as present.
		set := make(map[string]struct{}, len(locals))
		for _, local := range locals {
			set[local] = struct{}{}
		}
		present[imp.Path] = set
	}
	return present, true
}
