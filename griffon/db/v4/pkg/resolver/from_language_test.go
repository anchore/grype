package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"

	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nextlinux/griffon/griffon/db/v4/pkg/resolver/java"
	"github.com/nextlinux/griffon/griffon/db/v4/pkg/resolver/python"
	"github.com/nextlinux/griffon/griffon/db/v4/pkg/resolver/stock"
)

func TestFromLanguage(t *testing.T) {
	tests := []struct {
		language syftPkg.Language
		result   Resolver
	}{
		{
			language: syftPkg.Python,
			result:   &python.Resolver{},
		},
		{
			language: syftPkg.Java,
			result:   &java.Resolver{},
		},
		{
			language: syftPkg.Ruby,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Dart,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Rust,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Go,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.JavaScript,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Dotnet,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.PHP,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Ruby,
			result:   &stock.Resolver{},
		},
		{
			language: syftPkg.Language("something-new"),
			result:   &stock.Resolver{},
		},
	}

	for _, test := range tests {
		result, err := FromLanguage(test.language)
		assert.NoError(t, err)
		assert.Equal(t, result, test.result)
	}
}
