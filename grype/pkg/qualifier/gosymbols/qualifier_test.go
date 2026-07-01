package gosymbols

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

func TestGoSymbolsQualifier_Satisfied(t *testing.T) {
	binaryPkg := pkg.Package{
		Name: "golang.org/x/net",
		Metadata: pkg.GolangBinMetadata{
			Symbols: []string{
				"golang.org/x/net/html/charset.Lookup",
				"golang.org/x/net/html.(*Tokenizer).Next",
				"golang.org/x/net/html.Parse",
				"golang.org/x/net/http2.(*Framer[go.shape.int]).ReadFrame",
				"golang.org/x/net/html.(*Tokenizer).readComment-fm",
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
			Symbols: []string{
				"net/http.ListenAndServe",
				"net/http.(*Server).Serve",
				"net/http.(*http2Server).ServeConn",
				"net/http.(*Client).Do",
			},
		},
	}

	// stdlibClientPkg is a go binary that only makes HTTP *client* calls: it links net/http but none of
	// the vulnerable server symbols, so it must not match the server-side DoS (the false-positive grype
	// surfaced before symbol matching, when every net/http-linking binary matched the stdlib advisory).
	stdlibClientPkg := pkg.Package{
		Name: "stdlib",
		Metadata: pkg.GolangBinMetadata{
			Symbols: []string{
				"net/http.Get",
				"net/http.NewRequest",
				"net/http.(*Client).Do",
				"net/http.(*Transport).RoundTrip",
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
			name:      "vulnerable method symbol present in binary (pointer receiver normalization)",
			imports:   []Import{{Path: "golang.org/x/net/html", Symbols: []string{"Tokenizer.Next"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable generic method present in binary (type parameter normalization)",
			imports:   []Import{{Path: "golang.org/x/net/http2", Symbols: []string{"Framer.ReadFrame"}}},
			pkg:       binaryPkg,
			satisfied: true,
		},
		{
			name:      "vulnerable method present only as a method-value wrapper (-fm normalization)",
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

func Test_normalizeSymbol(t *testing.T) {
	tests := []struct {
		name   string
		symbol string
		want   string
	}{
		{
			name:   "plain function is unchanged",
			symbol: "golang.org/x/net/html.Parse",
			want:   "golang.org/x/net/html.Parse",
		},
		{
			name:   "value-receiver method is unchanged",
			symbol: "net/http.Header.Get",
			want:   "net/http.Header.Get",
		},
		{
			name:   "pointer-receiver decoration is removed",
			symbol: "net/http.(*Server).Serve",
			want:   "net/http.Server.Serve",
		},
		{
			name:   "generic instantiation loses its type parameters",
			symbol: "golang.org/x/net/http2.(*Framer[go.shape.int]).ReadFrame",
			want:   "golang.org/x/net/http2.Framer.ReadFrame",
		},
		{
			name:   "method-value wrapper suffix is removed",
			symbol: "golang.org/x/net/html.(*Tokenizer).readComment-fm",
			want:   "golang.org/x/net/html.Tokenizer.readComment",
		},
		{
			// known limitation: the type-parameter regex assumes a single, non-nested bracket
			// group, so a nested instantiation is not normalized to "pkg.T.M". This pins the
			// current (imperfect) behavior; the consequence is a missed match for that symbol,
			// not a false positive. See normalizeSymbol's doc comment.
			name:   "nested type parameter is not normalized cleanly (known limitation)",
			symbol: "example.com/pkg.(*Cache[go.shape.[]int]).Get",
			want:   "example.com/pkg.Cacheint].Get",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeSymbol(tt.symbol))
		})
	}
}
