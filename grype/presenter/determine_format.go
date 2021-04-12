package presenter

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/presenter/formats"
	"github.com/anchore/grype/grype/presenter/formats/cyclonedx"
	"github.com/anchore/grype/grype/presenter/formats/json"
	"github.com/anchore/grype/grype/presenter/formats/table"
	"github.com/anchore/grype/grype/presenter/formats/template"
)

// DetermineFormat returns a Format implementation that matches the given input.
// If validation of the given input fails, an error is returned.
func DetermineFormat(formatName, outputTemplateFile string) (formats.Format, error) {
	switch {
	case strings.EqualFold(formatName, json.Name):
		return json.Format, nil
	case strings.EqualFold(formatName, table.Name):
		return table.Format, nil
	case strings.EqualFold(formatName, cyclonedx.Name):
		return cyclonedx.Format, nil
	case strings.EqualFold(formatName, template.Name):
		return template.Format(outputTemplateFile)
	}

	return nil, fmt.Errorf("unsupported format %q, supported formats are: %s", formatName, AvailableFormats)
}

// AvailableFormats is a list of formats available for users to supply to DetermineFormat.
var AvailableFormats = []string{
	json.Name,
	table.Name,
	cyclonedx.Name,
	template.Name,
}
