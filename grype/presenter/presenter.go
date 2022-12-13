package presenter

import (
	"io"

	cyclonedxLib "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/grype/grype/presenter/cyclonedx"
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
	// NOTE: cyclonedx is identical to embeddedVEXJSON
	// The cyclonedx library only provides two BOM formats: JSON and XML
	case cycloneDXFormat:
		return cyclonedx.NewPresenter(pb, cyclonedxLib.BOMFileFormatJSON)
	case embeddedVEXJSON:
		return cyclonedx.NewPresenter(pb, cyclonedxLib.BOMFileFormatJSON)
	case embeddedVEXXML:
		return cyclonedx.NewPresenter(pb, cyclonedxLib.BOMFileFormatXML)
	case sarifFormat:
		return sarif.NewPresenter(pb)
	case templateFormat:
		return template.NewPresenter(pb, c.templateFilePath)
	default:
		return nil
	}
}
