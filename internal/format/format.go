package format

import (
	"strings"
)

const (
	UnknownFormat   Format = "unknown"
	JSONFormat      Format = "json"
	TableFormat     Format = "table"
	CycloneDXFormat Format = "cyclonedx"
	CycloneDXJSON   Format = "cyclonedx-json"
	CycloneDXXML    Format = "cyclonedx-xml"
	SarifFormat     Format = "sarif"
	TemplateFormat  Format = "template"

	// DEPRECATED <-- TODO: remove in v1.0
	EmbeddedVEXJSON Format = "embedded-cyclonedx-vex-json"
	EmbeddedVEXXML  Format = "embedded-cyclonedx-vex-xml"
)

// Format is a dedicated type to represent a specific kind of presenter output format.
type Format string

func (f Format) String() string {
	return string(f)
}

// Parse returns the presenter.format specified by the given user input.
func Parse(userInput string) Format {
	switch strings.ToLower(userInput) {
	case "":
		return TableFormat
	case strings.ToLower(JSONFormat.String()):
		return JSONFormat
	case strings.ToLower(TableFormat.String()):
		return TableFormat
	case strings.ToLower(SarifFormat.String()):
		return SarifFormat
	case strings.ToLower(TemplateFormat.String()):
		return TemplateFormat
	case strings.ToLower(CycloneDXFormat.String()):
		return CycloneDXFormat
	case strings.ToLower(CycloneDXJSON.String()):
		return CycloneDXJSON
	case strings.ToLower(CycloneDXXML.String()):
		return CycloneDXXML
	case strings.ToLower(EmbeddedVEXJSON.String()):
		return CycloneDXJSON
	case strings.ToLower(EmbeddedVEXXML.String()):
		return CycloneDXFormat
	default:
		return UnknownFormat
	}
}

// AvailableFormats is a list of presenter format options available to users.
var AvailableFormats = []Format{
	JSONFormat,
	TableFormat,
	CycloneDXFormat,
	CycloneDXJSON,
	SarifFormat,
	TemplateFormat,
}

// DeprecatedFormats TODO: remove in v1.0
var DeprecatedFormats = []Format{
	EmbeddedVEXJSON,
	EmbeddedVEXXML,
}
