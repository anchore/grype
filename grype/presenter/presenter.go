package presenter

import (
	"io"

	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/presenter/sarif"
	"github.com/anchore/grype/grype/presenter/table"
	"github.com/anchore/grype/grype/presenter/template"
	"github.com/anchore/grype/internal/log"
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
	// These embedded formats will be removed in v1.0
	case cycloneDXFormat:
		return cyclonedx.NewXMLPresenter(pb)
	case cycloneDXJSON:
		return cyclonedx.NewJSONPresenter(pb)
	case sarifFormat:
		return sarif.NewPresenter(pb)
	case templateFormat:
		return template.NewPresenter(pb, c.templateFilePath)
	// DEPRECATED TODO: remove in v1.0
	case embeddedVEXJSON:
		log.Warn("embedded-cyclonedx-vex-json format is deprecated and will be removed in v1.0")
		return cyclonedx.NewJSONPresenter(pb)
	case embeddedVEXXML:
		log.Warn("embedded-cyclonedx-vex-xml format is deprecated and will be removed in v1.0")
		return cyclonedx.NewXMLPresenter(pb)
	default:
		return nil
	}
}
