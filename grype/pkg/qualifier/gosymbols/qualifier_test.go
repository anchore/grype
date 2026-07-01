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
