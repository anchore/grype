package factory

import (
	"github.com/anchore/grype/grype/db/v4/pkg/resolver"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/java"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/python"
	"github.com/anchore/grype/grype/db/v4/pkg/resolver/stock"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func FromLanguage(language syftPkg.Language) (resolver.Resolver, error) {
	var r resolver.Resolver

	switch language {
	case syftPkg.Python:
		r = &python.Resolver{}
	case syftPkg.Java:
		r = &java.Resolver{}
	default:
		r = &stock.Resolver{}
	}

	return r, nil
}
