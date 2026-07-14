package pkg

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

type GolangBinMetadata struct {
	BuildSettings     pkg.KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string        `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string        `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string        `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string        `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string      `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`

	// Symbols are the function symbols compiled into the binary, grouped by the import path of the package
	// that owns them; each value is the list of symbol names local to that package (import path prefix
	// stripped). Populated only when syft cataloged the binary with symbol capture enabled.
	Symbols map[string][]string `json:"symbols,omitempty"`

	// symbolIndex is Symbols reshaped into import path -> set of normalized local symbol names, built
	// once when the package is provisioned so the gosymbols qualifier can intersect against an advisory's
	// symbol list with plain map lookups instead of normalizing on every candidate vulnerability. It is
	// derived state and intentionally not serialized.
	symbolIndex map[string]map[string]struct{}
}

// SymbolIndex returns the binary's function symbols as import path -> set of normalized local symbol
// names (govulndb's naming convention). The index is normalized once during package provisioning (see
// golangMetadataFromPkg); this accessor rebuilds it on demand for GolangBinMetadata values constructed
// directly, without going through the provider path (e.g. in tests). Returns nil when there are no
// symbols.
func (m GolangBinMetadata) SymbolIndex() map[string]map[string]struct{} {
	if m.symbolIndex != nil {
		return m.symbolIndex
	}
	return buildGoSymbolIndex(m.Symbols)
}

// buildGoSymbolIndex reshapes syft's grouped symbol lists into import path -> set of normalized local
// symbol names. Normalization happens here, once per package, rather than inside the qualifier's
// per-vulnerability search.
func buildGoSymbolIndex(symbols map[string][]string) map[string]map[string]struct{} {
	if len(symbols) == 0 {
		return nil
	}
	index := make(map[string]map[string]struct{}, len(symbols))
	for importPath, locals := range symbols {
		set := make(map[string]struct{}, len(locals))
		for _, local := range locals {
			set[NormalizeGoSymbol(local)] = struct{}{}
		}
		index[importPath] = set
	}
	return index
}

var goSymbolTypeParamPattern = regexp.MustCompile(`\[[^]]*]`)

// NormalizeGoSymbol converts a symbol name as found in a binary symbol table into govulndb's symbol
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
func NormalizeGoSymbol(symbol string) string {
	symbol = strings.ReplaceAll(symbol, "(*", "")
	symbol = strings.ReplaceAll(symbol, ")", "")
	symbol = strings.TrimSuffix(symbol, "-fm")
	return goSymbolTypeParamPattern.ReplaceAllString(symbol, "")
}

type GolangModMetadata struct {
	H1Digest string `json:"h1Digest,omitempty"`
}

type GolangSourceMetadata struct {
	H1Digest        string `json:"h1Digest,omitempty"`
	OperatingSystem string `json:"os,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	BuildTags       string `json:"buildTags,omitempty"`
	CgoEnabled      bool   `json:"cgoEnabled"`
}
