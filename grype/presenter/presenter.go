package presenter

import (
	"io"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/scope"

	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/result"
	"github.com/anchore/syft/syft/pkg"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(option Option, results result.Result, catalog *pkg.Catalog, theScope scope.Scope, metadataProvider vulnerability.MetadataProvider) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter(results, catalog, theScope, metadataProvider)
	case TablePresenter:
		return table.NewPresenter(results, catalog)
	default:
		return nil
	}
}
