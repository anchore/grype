package presenter

import (
	"strings"
)

const (
	unknownFormat   format = "unknown"
	jsonFormat      format = "json"
	tableFormat     format = "table"
	cycloneDXFormat format = "cyclonedx"
	templateFormat  format = "template"
)

// format is a dedicated type to represent a specific kind of presenter output format.
type format string

func (f format) String() string {
	return string(f)
}

// parse returns the presenter.format specified by the given user input.
func parse(userInput string) format {
	switch strings.ToLower(userInput) {
	case "":
		return tableFormat
	case strings.ToLower(jsonFormat.String()):
		return jsonFormat
	case strings.ToLower(tableFormat.String()):
		return tableFormat
	case strings.ToLower(cycloneDXFormat.String()):
		return cycloneDXFormat
	case strings.ToLower(templateFormat.String()):
		return templateFormat
	default:
		return unknownFormat
	}
}
