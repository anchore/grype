package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/db/v4/pkg/resolver/java"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/python"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/stock"
	syftPkg "github.com/anchore/syft/syft/pkg"
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
