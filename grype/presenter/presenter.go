package presenter

import (
	"io"

	"github.com/anchore/grype/grype"

	"github.com/anchore/grype/grype/presenter/template"

	"github.com/anchore/grype/grype/presenter/cyclonedx"
	"github.com/anchore/grype/grype/presenter/json"
	"github.com/anchore/grype/grype/presenter/table"
)

// Presenter is the main interface other Presenters need to implement
type Presenter interface {
	Present(io.Writer, grype.Analysis) error
}

// GetPresenter retrieves a Presenter that matches a CLI option
func GetPresenter(outputFormat, outputTemplateFile string) (Presenter, error) {
	c, err := validatedConfig(outputFormat, outputTemplateFile)
	if err != nil {
		return nil, err
	}

	switch c.format {
	case jsonFormat:
		return json.NewPresenter(), nil
	case tableFormat:
		return table.NewPresenter(), nil
	case cycloneDXFormat:
		return cyclonedx.NewPresenter(), nil
	case templateFormat:
		return template.NewPresenter(c.templateFilePath), nil
	default:
		return nil, nil // TODO: Handle this; we should never encounter this case
	}
}

// AvailableFormats is a list of presenter format options available to users.
var AvailableFormats = []string{
	json.Name,
	table.Name,
	cyclonedx.Name,
	template.Name,
}
