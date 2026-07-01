package gosymbols

import (
	"regexp"
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

// Satisfied reports whether the package plausibly uses any of the vulnerable symbols. The check
// only applies when the scanned package carries binary symbol evidence (go binaries cataloged with
// symbol capture enabled); packages without symbol evidence always satisfy the qualifier so that
// module-granularity matching behavior is preserved.
func (q gosymbolsQualifier) Satisfied(p pkg.Package) (bool, error) {
	if len(q.imports) == 0 {
		return true, nil
	}

	m, ok := p.Metadata.(pkg.GolangBinMetadata)
	if !ok || len(m.Symbols) == 0 {
		return true, nil
	}

	present := make(map[string]struct{}, len(m.Symbols))
	for _, sym := range m.Symbols {
		present[normalizeSymbol(sym)] = struct{}{}
	}

	for _, imp := range q.imports {
		if len(imp.Symbols) == 0 {
			// the entire package is vulnerable: any symbol from the package counts
			prefix := imp.Path + "."
			for sym := range present {
				if strings.HasPrefix(sym, prefix) {
					return true, nil
				}
			}
			continue
		}
		for _, vulnSym := range imp.Symbols {
			if _, found := present[imp.Path+"."+vulnSym]; found {
				return true, nil
			}
		}
	}

	return false, nil
}

var typeParamPattern = regexp.MustCompile(`\[[^]]*]`)

// normalizeSymbol converts a symbol name as found in a binary symbol table into govulndb's symbol
// naming convention so the two can be compared:
//   - pointer-receiver decoration is removed: "pkg.(*T).M" -> "pkg.T.M"
//   - generic instantiations lose their type parameters: "pkg.(*T[go.shape.int]).M" -> "pkg.T.M"
//   - the compiler's "-fm" method-value-wrapper suffix is removed: "pkg.(*T).M-fm" -> "pkg.T.M".
//     A method-value wrapper is emitted when a method is referenced as a value (e.g. passed as a
//     callback), so its presence means the underlying method is used.
func normalizeSymbol(symbol string) string {
	symbol = strings.ReplaceAll(symbol, "(*", "")
	symbol = strings.ReplaceAll(symbol, ")", "")
	symbol = strings.TrimSuffix(symbol, "-fm")
	return typeParamPattern.ReplaceAllString(symbol, "")
}
