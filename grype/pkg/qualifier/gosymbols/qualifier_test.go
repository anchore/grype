package gosymbols

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier"
)

// symbol names below are already in govulndb's normalized convention: the provider normalizes a
// binary's symbol table once when the package is built (pkg.normalizeGoSymbols), so the qualifier
// only ever sees normalized names. The normalization itself is covered by pkg's golang_symbol_test.go.
func TestGoSymbolsQualifier_Satisfied(t *testing.T) {
	binaryPkg := pkg.Package{
		Name: "golang.org/x/net",
		Metadata: pkg.GolangBinMetadata{
			Symbols: map[string][]string{
				"golang.org/x/net/html/charset": {"Lookup"},
				"golang.org/x/net/html": {
					"Tokenizer.Next",
					"Parse",
					"Tokenizer.readComment",
				},
				"golang.org/x/net/http2": {"Framer.ReadFrame"},
			},
		},
	}

	noSymbolsPkg := pkg.Package{
		Name:     "golang.org/x/net",
		Metadata: pkg.GolangBinMetadata{},
	}

	// stdlibHTTPServerVuln mirrors the ecosystem_specific.imports for the "stdlib" module in
	// GO-2022-0969 (net/http HTTP/2 server DoS) as carried into the DB by the govulndb transformer.
	// The listed symbols are all server-side entrypoints.
	stdlibHTTPServerVuln := []Import{{
		Path: "net/http",
		Symbols: []string{
			"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS",
			"Server.ListenAndServe", "Server.ListenAndServeTLS", "Server.Serve", "Server.ServeTLS",
			"http2Server.ServeConn", "http2serverConn.goAway",
		},
	}}

	// stdlibServerPkg is a go binary that runs an HTTP server: its captured stdlib symbols include the
	// vulnerable net/http server entrypoints. Symbol strings use syft's binary naming (import-path
	// qualified, pointer-receiver decorated); the bundled HTTP/2 code appears under the http2* prefix.
	stdlibServerPkg := pkg.Package{
		Name: "stdlib",
		Metadata: pkg.GolangBinMetadata{
			Symbols: map[string][]string{
				"net/http": {
					"ListenAndServe",
					"Server.Serve",
					"http2Server.ServeConn",
					"Client.Do",
				},
			},
		},
	}

	// stdlibClientPkg is a go binary that only makes HTTP *client* calls: it links net/http but none of
	// the vulnerable server symbols, so it must not match the server-side DoS (the false-positive grype
	// surfaced before symbol matching, when every net/http-linking binary matched the stdlib advisory).
	stdlibClientPkg := pkg.Package{
		Name: "stdlib",
		Metadata: pkg.GolangBinMetadata{
			Symbols: map[string][]string{
				"net/http": {
					"Get",
					"NewRequest",
					"Client.Do",
					"Transport.RoundTrip",
				},
			},
		},
	}

	tests := []struct {
		name      string
		imports   []Import
		pkg       pkg.Package
		satisfied bool
	}{
		{
			name:      "no import info on vulnerability always satisfies",
			imports:   nil,
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "package without symbol evidence always satisfies",
			imports:   []Import{{Path: "golang.org/x/net/websocket", Symbols: []string{"Dial"}}},
			pkg:       noSymbolsPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable function symbol present in binary",
			imports:   []Import{{Path: "golang.org/x/net/html/charset", Symbols: []string{"Lookup"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable method symbol present in binary",
			imports:   []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Tokenizer.Next"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable generic method present in binary",
			imports:   []Import{{Path: "golang.org/x/net/http2", Symbols: []string{"Framer.ReadFrame"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "another vulnerable method present in binary",
			imports:   []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Tokenizer.readComment"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable symbol not present in binary",
			imports:   []Import{{Path: "golang.org/x/net/html", Symbols: []string{"ParseFragment"}}},
			pkg:       binaryPkg,
			satisfied: false,
		},
		{
			name:      "vulnerable package not compiled into binary",
			imports:   []Import{{Path: "golang.org/x/net/websocket", Symbols: []string{"Dial"}}},
			pkg:       binaryPkg,
			satisfied: false,
		},
		{
			name:      "import without symbols means whole package is vulnerable - package present",
			imports:   []Import{{Path: "golang.org/x/net/html"}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "import without symbols means whole package is vulnerable - package absent",
			imports:   []Import{{Path: "golang.org/x/net/websocket"}},
			pkg:       binaryPkg,
			satisfied: false,
		},
		{
			name: "any of multiple imports satisfies",
			imports: []Import{
				{Path: "golang.org/x/net/websocket", Symbols: []string{"Dial"}},
				{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}},
			},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "stdlib http server binary matches the net/http server vuln",
			imports:   stdlibHTTPServerVuln,
			pkg:       stdlibServerPkg,
			satisfied: true,
		},
		{
			name:      "stdlib bundled http2 server method matches (http2* prefix, pointer-receiver normalization)",
			imports:   []Import{{Path: "net/http", Symbols: []string{"http2Server.ServeConn"}}},
			pkg:       stdlibServerPkg,
			satisfied: true,
		},
		{
			name:      "stdlib http client-only binary does not match the net/http server vuln (no false positive)",
			imports:   stdlibHTTPServerVuln,
			pkg:       stdlibClientPkg,
			satisfied: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.imports)
			satisfied, err := q.Satisfied(tt.pkg)
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, satisfied)
		})
	}
}

func TestGoSymbolsQualifier_MatchedSymbols(t *testing.T) {
	// binaryPkg carries symbols already normalized to govulndb's convention (the provider normalizes
	// at build time); MatchedSymbols reports hits in that same convention.
	binaryPkg := pkg.Package{
		Name: "golang.org/x/net",
		Metadata: pkg.GolangBinMetadata{
			Symbols: map[string][]string{
				"golang.org/x/net/html": {
					"Parse",
					"Tokenizer.Next",
					"Tokenizer.readComment",
				},
				"golang.org/x/net/http2": {"Framer.ReadFrame"},
			},
		},
	}

	noSymbolsPkg := pkg.Package{
		Name:     "golang.org/x/net",
		Metadata: pkg.GolangBinMetadata{},
	}

	tests := []struct {
		name    string
		imports []Import
		pkg     pkg.Package
		want    []string
	}{
		{
			name:    "single named hit reported in advisory convention",
			imports: []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}}},
			pkg:     binaryPkg,
			want:    []string{"golang.org/x/net/html.Parse"},
		},
		{
			name:    "method hit normalized from pointer receiver",
			imports: []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Tokenizer.Next"}}},
			pkg:     binaryPkg,
			want:    []string{"golang.org/x/net/html.Tokenizer.Next"},
		},
		{
			name: "multiple hits are sorted and de-duplicated",
			imports: []Import{
				{Path: "golang.org/x/net/html", Symbols: []string{"Tokenizer.Next", "Parse"}},
				{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}}, // duplicate path+symbol
				{Path: "golang.org/x/net/http2", Symbols: []string{"Framer.ReadFrame"}},
			},
			pkg: binaryPkg,
			want: []string{
				"golang.org/x/net/html.Parse",
				"golang.org/x/net/html.Tokenizer.Next",
				"golang.org/x/net/http2.Framer.ReadFrame",
			},
		},
		{
			name:    "whole-package hit reports the import path alone",
			imports: []Import{{Path: "golang.org/x/net/html"}},
			pkg:     binaryPkg,
			want:    []string{"golang.org/x/net/html"},
		},
		{
			name:    "whole-package absent reports nothing",
			imports: []Import{{Path: "golang.org/x/net/websocket"}},
			pkg:     binaryPkg,
			want:    nil,
		},
		{
			name:    "no symbol evidence reports nothing (module-granularity match)",
			imports: []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Parse"}}},
			pkg:     noSymbolsPkg,
			want:    nil,
		},
		{
			name:    "no intersection reports nothing",
			imports: []Import{{Path: "golang.org/x/net/html", Symbols: []string{"ParseFragment"}}},
			pkg:     binaryPkg,
			want:    nil,
		},
		{
			name:    "no import info reports nothing",
			imports: nil,
			pkg:     binaryPkg,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := New(tt.imports)
			assert.Equal(t, tt.want, MatchedSymbols([]qualifier.Qualifier{q}, tt.pkg))
		})
	}
}
