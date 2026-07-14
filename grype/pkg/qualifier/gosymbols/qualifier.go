package gosymbols

import (
	"regexp"
	"sort"
	"strings"

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

// SymbolReporter is implemented by qualifiers that can report which vulnerable symbols a package
// was found to use. Match construction type-asserts to this so it can surface the intersection
// that caused a symbol-scoped match.
type SymbolReporter interface {
	MatchedSymbols(p pkg.Package) []string
}

// Satisfied reports whether the package plausibly uses any of the vulnerable symbols. The check
// only applies when the scanned package carries binary symbol evidence (go binaries cataloged with
// symbol capture enabled); packages without symbol evidence always satisfy the qualifier so that
// module-granularity matching behavior is preserved.
func (q *gosymbolsQualifier) Satisfied(p pkg.Package) (bool, error) {
	if len(q.imports) == 0 {
		return true, nil
	}

	present, ok := q.present(p)
	if !ok {
		// no symbol evidence: preserve module-granularity matching
		return true, nil
	}

	for _, imp := range q.imports {
		if usesImport(imp, present) {
			return true, nil
		}
	}

	return false, nil
}

// MatchedSymbols returns the fully-qualified vulnerable symbols the package is found to use, sorted
// and de-duplicated. A whole-package (symbol-less) advisory import contributes its import path
// alone. It returns nil when the package carries no symbol evidence (module-granularity matching)
// or uses none of the vulnerable symbols — i.e. whenever there is no concrete intersection to
// report.
func (q *gosymbolsQualifier) MatchedSymbols(p pkg.Package) []string {
	if len(q.imports) == 0 {
		return nil
	}

	present, ok := q.present(p)
	if !ok {
		return nil
	}

	seen := make(map[string]struct{})
	var matched []string
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
	return matched
}

// present returns the package's binary symbol evidence, as import path -> set of normalized local
// symbol names, restricted to the import paths this advisory actually references (q.imports), plus
// whether such evidence exists. Only the referenced paths are normalized: usesImport and
// MatchedSymbols only ever look up present[imp.Path], so normalizing the whole symbol table (hundreds
// of import paths on a real binary) would be wasted work. Packages without symbol evidence (not a go
// binary, or cataloged without symbol capture) report ok=false so callers fall back to
// module-granularity matching.
func (q *gosymbolsQualifier) present(p pkg.Package) (map[string]map[string]struct{}, bool) {
	m, ok := p.Metadata.(pkg.GolangBinMetadata)
	if !ok || len(m.Symbols) == 0 {
		return nil, false
	}

	present := make(map[string]map[string]struct{}, len(q.imports))
	for _, imp := range q.imports {
		if _, done := present[imp.Path]; done {
			continue // path already normalized (advisory referenced it more than once)
		}
		locals, ok := m.Symbols[imp.Path]
		if !ok {
			continue // import path not present in the binary; leave it absent
		}
		// a path present with an empty local list still yields an (empty) set entry, so the
		// whole-package present check (usesImport / MatchedSymbols) sees the path as present.
		set := make(map[string]struct{}, len(locals))
		for _, local := range locals {
			set[normalizeSymbol(local)] = struct{}{}
		}
		present[imp.Path] = set
	}
	return present, true
}

var typeParamPattern = regexp.MustCompile(`\[[^]]*]`)

// normalizeSymbol converts a symbol name as found in a binary symbol table into govulndb's symbol
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
func normalizeSymbol(symbol string) string {
	symbol = strings.ReplaceAll(symbol, "(*", "")
	symbol = strings.ReplaceAll(symbol, ")", "")
	symbol = strings.TrimSuffix(symbol, "-fm")
	return typeParamPattern.ReplaceAllString(symbol, "")
}

// usesImport reports whether any of the import's vulnerable symbols is present. A symbol-less
// import (the whole package is vulnerable) is satisfied whenever the import path is present at all.
func usesImport(imp Import, present map[string]map[string]struct{}) bool {
	locals, ok := present[imp.Path]
	if !ok {
		return false
	}
	if len(imp.Symbols) == 0 {
		return true
	}
	for _, vulnSym := range imp.Symbols {
		if _, ok := locals[vulnSym]; ok {
			return true
		}
	}
	return false
}
