package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_normalizeGoSymbol(t *testing.T) {
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
			// not a false positive. See normalizeGoSymbol's doc comment.
			name:   "nested type parameter is not normalized cleanly (known limitation)",
			symbol: "example.com/pkg.(*Cache[go.shape.[]int]).Get",
			want:   "example.com/pkg.Cacheint].Get",
		},

		// --- cases below are real symbols mined verbatim from a syft SBOM (/tmp/all-syms.json) ---

		// plain functions / package-level names: unchanged
		{
			name:   "main package function is unchanged",
			symbol: "main.main",
			want:   "main.main",
		},
		{
			name:   "plain exported function is unchanged",
			symbol: "dario.cat/mergo.Merge",
			want:   "dario.cat/mergo.Merge",
		},
		{
			name:   "package init is unchanged",
			symbol: "github.com/acarl005/stripansi.init",
			want:   "github.com/acarl005/stripansi.init",
		},
		{
			name:   "numbered init variant is unchanged",
			symbol: "github.com/adrg/xdg.init.0",
			want:   "github.com/adrg/xdg.init.0",
		},
		{
			name:   "compiler map.init name is unchanged",
			symbol: "github.com/aws/aws-sdk-go-v2/aws/middleware.map.init.0",
			want:   "github.com/aws/aws-sdk-go-v2/aws/middleware.map.init.0",
		},
		{
			name:   "value-receiver method is unchanged (real)",
			symbol: "runtime.offAddr.equal",
			want:   "runtime.offAddr.equal",
		},

		// closures: the func<N> suffix is not touched
		{
			name:   "closure func1 suffix is unchanged",
			symbol: "github.com/anchore/clio.async.func1",
			want:   "github.com/anchore/clio.async.func1",
		},
		{
			name:   "nested closure funcN suffix is unchanged",
			symbol: "github.com/anchore/bubbly/bubbles/taskprogress.New.WithWidth.func3",
			want:   "github.com/anchore/bubbly/bubbles/taskprogress.New.WithWidth.func3",
		},
		{
			name:   "closure inside init is unchanged",
			symbol: "github.com/aws/aws-sdk-go-v2/aws/defaults.init.func1",
			want:   "github.com/aws/aws-sdk-go-v2/aws/defaults.init.func1",
		},

		// pointer-receiver decoration removed
		{
			name:   "pointer-receiver method (real)",
			symbol: "github.com/aws/aws-sdk-go-v2/aws/retry.(*AdaptiveMode).handleResponse",
			want:   "github.com/aws/aws-sdk-go-v2/aws/retry.AdaptiveMode.handleResponse",
		},
		{
			name:   "pointer-receiver init method",
			symbol: "github.com/anchore/go-logger/adapter/logrus.(*TextFormatter).init",
			want:   "github.com/anchore/go-logger/adapter/logrus.TextFormatter.init",
		},

		// middle-dot (·) compiler-disambiguated type names
		{
			name:   "pointer-receiver with middle-dot numeric suffix",
			symbol: "mime/multipart.(*writerOnly·1).Write",
			want:   "mime/multipart.writerOnly·1.Write",
		},
		{
			name:   "value-receiver with middle-dot numeric suffix is unchanged aside from nothing",
			symbol: "mime/multipart.writerOnly·1.Write",
			want:   "mime/multipart.writerOnly·1.Write",
		},

		// -fm method-value wrappers: suffix removed (plus any pointer strip)
		{
			name:   "pointer-receiver method value wrapper",
			symbol: "github.com/aws/aws-sdk-go-v2/aws/retry.(*Standard).noRetryIncrement-fm",
			want:   "github.com/aws/aws-sdk-go-v2/aws/retry.Standard.noRetryIncrement",
		},
		{
			name:   "value-receiver method value wrapper",
			symbol: "github.com/aws/aws-sdk-go-v2/aws.EndpointResolver.ResolveEndpoint-fm",
			want:   "github.com/aws/aws-sdk-go-v2/aws.EndpointResolver.ResolveEndpoint",
		},
		{
			name:   "unexported value-receiver method value wrapper",
			symbol: "github.com/aws/aws-sdk-go-v2/aws/ratelimit.rateToken.release-fm",
			want:   "github.com/aws/aws-sdk-go-v2/aws/ratelimit.rateToken.release",
		},
		{
			name:   "pointer-receiver method value wrapper (quill)",
			symbol: "github.com/anchore/quill/cmd/quill/cli/ui.(*Handler).handleTask-fm",
			want:   "github.com/anchore/quill/cmd/quill/cli/ui.Handler.handleTask",
		},

		// generic instantiations: type-parameter group stripped
		{
			name:   "generic function with string type param",
			symbol: "github.com/charmbracelet/x/ansi.DecodeSequence[go.shape.string]",
			want:   "github.com/charmbracelet/x/ansi.DecodeSequence",
		},
		{
			name:   "generic function with uint32 type param",
			symbol: "github.com/charmbracelet/x/ansi.shift[go.shape.uint32]",
			want:   "github.com/charmbracelet/x/ansi.shift",
		},
		{
			name:   "pointer-receiver generic method (combined strip)",
			symbol: "github.com/clipperhouse/uax29/v2/graphemes.(*Iterator[go.shape.string]).Next",
			want:   "github.com/clipperhouse/uax29/v2/graphemes.Iterator.Next",
		},
		{
			// struct-shaped type param has no ']' inside its group, so it strips cleanly even though
			// it is a big, gnarly-looking bracket group.
			name:   "generic with struct-shaped type param",
			symbol: "github.com/anchore/fangs.set[go.shape.struct { reflect.typ_ *internal/abi.Type; reflect.ptr unsafe.Pointer; reflect.flag }].add",
			want:   "github.com/anchore/fangs.set.add",
		},
		{
			// the interface method's "()" is stripped by the paren pass, but it sits inside the
			// bracket group that the type-param pass removes wholesale, so the result is still clean.
			name:   "generic with interface-shaped type param containing parens",
			symbol: "github.com/aws/aws-sdk-go-v2/service/s3.timeOperationMetric[go.shape.interface { Expiration() time.Time }]",
			want:   "github.com/aws/aws-sdk-go-v2/service/s3.timeOperationMetric",
		},
		{
			name:   "generic instantiation followed by a closure suffix",
			symbol: "github.com/aws/aws-sdk-go-v2/service/s3.timeOperationMetric[go.shape.interface {}].withOperationMetadata.func1",
			want:   "github.com/aws/aws-sdk-go-v2/service/s3.timeOperationMetric.withOperationMetadata.func1",
		},

		// nested type-parameter groups ([]T) exercise the documented known limitation: the single-group
		// regex stops at the inner "]", leaving a mangled tail. These pin the imperfect output; the
		// consequence is a MISSED match for that symbol, not a false positive.
		{
			name:   "nested slice type param is not normalized cleanly (known limitation)",
			symbol: "github.com/clipperhouse/displaywidth.graphemeWidth[go.shape.[]uint8]",
			want:   "github.com/clipperhouse/displaywidth.graphemeWidthuint8]",
		},
		{
			name:   "pointer-receiver + nested slice type param (known limitation)",
			symbol: "github.com/clipperhouse/uax29/v2/graphemes.(*Iterator[go.shape.[]uint8]).Next",
			want:   "github.com/clipperhouse/uax29/v2/graphemes.Iteratoruint8].Next",
		},
		{
			name:   "pointer-receiver + nested slice-of-named-type param + closure (known limitation)",
			symbol: "github.com/anchore/bubbly/bubbles/frame.(*Frame).Update.Batch.compactCmds[go.shape.[]github.com/charmbracelet/bubbletea.Cmd].func2",
			want:   "github.com/anchore/bubbly/bubbles/frame.Frame.Update.Batch.compactCmdsgithub.com/charmbracelet/bubbletea.Cmd].func2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeGoSymbol(tt.symbol))
		})
	}
}

func Test_normalizeGoSymbols(t *testing.T) {
	t.Run("nil in, nil out", func(t *testing.T) {
		assert.Nil(t, normalizeGoSymbols(nil))
	})

	t.Run("normalizes and de-duplicates per path, preserving empty lists", func(t *testing.T) {
		got := normalizeGoSymbols(map[string][]string{
			"net/http": {
				"(*Server).Serve",
				"(*Server).Serve-fm", // normalizes to the same name as above -> deduped
				"Get",
			},
			"crypto/tls": {}, // whole-package presence marker must survive
		})
		assert.Equal(t, map[string][]string{
			"net/http":   {"Server.Serve", "Get"},
			"crypto/tls": {},
		}, got)
	})

	t.Run("does not mutate the input map's slices", func(t *testing.T) {
		in := map[string][]string{"net/http": {"(*Server).Serve"}}
		_ = normalizeGoSymbols(in)
		assert.Equal(t, []string{"(*Server).Serve"}, in["net/http"], "input must be left untouched")
	})

	t.Run("real generic instantiations collapse to one name (dedup)", func(t *testing.T) {
		// three real go.shape instantiations of s3.timeOperationMetric all normalize to the same
		// name and must collapse to a single entry.
		got := normalizeGoSymbols(map[string][]string{
			"github.com/aws/aws-sdk-go-v2/service/s3": {
				"timeOperationMetric[go.shape.interface { Expiration() time.Time }]",
				"timeOperationMetric[go.shape.interface {}]",
				"timeOperationMetric[go.shape.struct { URI net/url.URL; Headers net/http.Header; Properties github.com/aws/smithy-go.Properties }]",
			},
			"github.com/anchore/fangs": {}, // whole-package presence marker must survive
		})
		assert.Equal(t, map[string][]string{
			"github.com/aws/aws-sdk-go-v2/service/s3": {"timeOperationMetric"},
			"github.com/anchore/fangs":                {},
		}, got)
	})
}
