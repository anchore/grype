package presenter

import (
	"io"

	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/presenter/sarif"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/presenter/template"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
// TODO dependency cycle with presenter package to sub formats
func GetPresenter(c Config, pb models.PresenterBundle) Presenter {
	switch c.format {
	case jsonFormat:
		return json.NewPresenter(pb)
	case tableFormat:
		if c.showSuppressed {
			return table.NewPresenter(pb)
		}
		return table.NewPresenter(pb)
	case sarifFormat:
		return sarif.NewPresenter(pb)
	case templateFormat:
		return template.NewPresenter(pb, c.templateFilePath)
	default:
		return nil
	}
}
