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
func GetPresenters(c Config, pb models.PresenterConfig) (presenters []Presenter) {
	for _, f := range c.formats {
		switch f.id {
		case jsonFormat:
			presenters = append(presenters, json.NewPresenter(pb, f.outputFilePath))
		case tableFormat:
			presenters = append(presenters, table.NewPresenter(pb, c.showSuppressed))

		// NOTE: cyclonedx is identical to embeddedVEXJSON
		// The cyclonedx library only provides two BOM formats: JSON and XML
		// These embedded formats will be removed in v1.0
		case cycloneDXFormat:
			presenters = append(presenters, cyclonedx.NewXMLPresenter(pb))
		case cycloneDXJSON:
			presenters = append(presenters, cyclonedx.NewJSONPresenter(pb))
		case cycloneDXXML:
			presenters = append(presenters, cyclonedx.NewXMLPresenter(pb))
		case sarifFormat:
			presenters = append(presenters, sarif.NewPresenter(pb))
		case templateFormat:
			presenters = append(presenters, template.NewPresenter(pb, f.outputFilePath, c.templateFilePath))
		// DEPRECATED TODO: remove in v1.0
		case embeddedVEXJSON:
			log.Warn("embedded-cyclonedx-vex-json format is deprecated and will be removed in v1.0")
			presenters = append(presenters, cyclonedx.NewJSONPresenter(pb))
		case embeddedVEXXML:
			log.Warn("embedded-cyclonedx-vex-xml format is deprecated and will be removed in v1.0")
			presenters = append(presenters, cyclonedx.NewXMLPresenter(pb))
		}
	}
	if len(presenters) == 0 {
		presenters = append(presenters, table.NewPresenter(pb, c.showSuppressed))
	}
	log.Info(presenters)
	return presenters
}
