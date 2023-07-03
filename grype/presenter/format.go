package presenter

import (
	"strings"
)

const (
	unknownFormat   id = "unknown"
	jsonFormat      id = "json"
	tableFormat     id = "table"
	cycloneDXFormat id = "cyclonedx"
	cycloneDXJSON   id = "cyclonedx-json"
	cycloneDXXML    id = "cyclonedx-xml"
	sarifFormat     id = "sarif"
	templateFormat  id = "template"

	// DEPRECATED <-- TODO: remove in v1.0
	embeddedVEXJSON id = "embedded-cyclonedx-vex-json"
	embeddedVEXXML  id = "embedded-cyclonedx-vex-xml"
)

// format is a dedicated type to represent a specific kind of presenter output format.
type id string

type format struct {
	id             id
	outputFilePath string
}

func (f id) String() string {
	return string(f)
}

// parse returns the presenter.format specified by the given user input.
func parse(userInput string) format {
	switch strings.ToLower(userInput) {
	case "":
		return format{id: tableFormat}
	case strings.ToLower(jsonFormat.String()):
		return format{id: jsonFormat}
	case strings.ToLower(tableFormat.String()):
		return format{id: tableFormat}
	case strings.ToLower(sarifFormat.String()):
		return format{id: sarifFormat}
	case strings.ToLower(templateFormat.String()):
		return format{id: templateFormat}
	case strings.ToLower(cycloneDXFormat.String()):
		return format{id: cycloneDXFormat}
	case strings.ToLower(cycloneDXJSON.String()):
		return format{id: cycloneDXJSON}
	case strings.ToLower(cycloneDXXML.String()):
		return format{id: cycloneDXXML}
	case strings.ToLower(embeddedVEXJSON.String()):
		return format{id: cycloneDXJSON}
	case strings.ToLower(embeddedVEXXML.String()):
		return format{id: cycloneDXFormat}
	default:
		return format{id: unknownFormat}
	}
}

// AvailableFormats is a list of presenter format options available to users.
var AvailableFormats = []id{
	jsonFormat,
	tableFormat,
	cycloneDXFormat,
	cycloneDXJSON,
	sarifFormat,
	templateFormat,
}

var DefaultFormat = tableFormat

// DeprecatedFormats TODO: remove in v1.0
var DeprecatedFormats = []id{
	embeddedVEXJSON,
	embeddedVEXXML,
}
