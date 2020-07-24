package presenter

import (
	"io"

	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/result"
	"github.com/anchore/syft/syft/pkg"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer, *pkg.Catalog, result.Result) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(option Option) Presenter {
	switch option {
	case JSONPresenter:
		return json.NewPresenter()
	default:
		return nil
	}
}
