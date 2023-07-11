package presenter

import (
	"github.com/wagoodman/go-presenter"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/format"
)

// GetPresenter retrieves a Presenter that matches a CLI option.
// Deprecated: this will be removed in v1.0
func GetPresenter(f string, templatePath string, showSuppressed bool, pb models.PresenterConfig) presenter.Presenter {
	return format.GetPresenter(format.Parse(f), format.PresentationConfig{
		TemplateFilePath: templatePath,
		ShowSuppressed:   showSuppressed,
	}, pb)
}
