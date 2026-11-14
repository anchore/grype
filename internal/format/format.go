package format

import (
	"strings"
)

var (
	UnknownFormat       = Format{name: "unknown", version: ""}
	JSONFormat          = Format{name: "json", version: ""}
	TableFormat         = Format{name: "table", version: ""}
	CycloneDXFormat     = Format{name: "cyclonedx", version: ""}
	CycloneDXJSON       = Format{name: "cyclonedx-json", version: ""}
	CycloneDXXML        = Format{name: "cyclonedx-xml", version: ""}
	CycloneDXFormatv1_5 = Format{name: "cyclonedx", version: "1.5"}
	CycloneDXJSONv1_5   = Format{name: "cyclonedx-json", version: "1.5"}
	CycloneDXXMLv1_5    = Format{name: "cyclonedx-xml", version: "1.5"}
	SarifFormat         = Format{name: "sarif", version: ""}
	TemplateFormat      = Format{name: "template", version: ""}

	// DEPRECATED <-- TODO: remove in v1.0
	EmbeddedVEXJSON = Format{name: "embedded-cyclonedx-vex-json", version: ""}
	EmbeddedVEXXML  = Format{name: "embedded-cyclonedx-vex-xml", version: ""}
)

// Format is a dedicated type to represent a specific kind of presenter output format.
type Format struct {
	name    string
	version string
}

func (f Format) String() string {
	if f.version != "" {
		return f.name + "@" + f.version
	}
	return f.name
}

// Parse returns the presenter.format specified by the given user input.
func Parse(userInput string) Format {
	parts := strings.SplitN(userInput, "@", 2)
	version := ""

	if len(parts) > 1 {
		version = parts[1]
	}

	result := UnknownFormat
	switch strings.ToLower(parts[0]) {
	case "":
		result = TableFormat
	case strings.ToLower(JSONFormat.String()):
		result = JSONFormat
	case strings.ToLower(TableFormat.String()):
		result = TableFormat
	case strings.ToLower(SarifFormat.String()):
		result = SarifFormat
	case strings.ToLower(TemplateFormat.String()):
		result = TemplateFormat
	case strings.ToLower(CycloneDXFormat.String()):
		result = CycloneDXFormat
	case strings.ToLower(CycloneDXJSON.String()):
		result = CycloneDXJSON
	case strings.ToLower(CycloneDXXML.String()):
		result = CycloneDXXML
	case strings.ToLower(EmbeddedVEXJSON.String()):
		result = CycloneDXJSON
	case strings.ToLower(EmbeddedVEXXML.String()):
		result = CycloneDXFormat
	default:
		result = UnknownFormat
	}

	result.version = version
	return result
}

// AvailableFormats is a list of presenter format options available to users.
var AvailableFormats = []Format{
	JSONFormat,
	TableFormat,
	CycloneDXFormat,
	CycloneDXJSON,
	CycloneDXFormatv1_5,
	CycloneDXJSONv1_5,
	SarifFormat,
	TemplateFormat,
}

// DeprecatedFormats TODO: remove in v1.0
var DeprecatedFormats = []Format{
	EmbeddedVEXJSON,
	EmbeddedVEXXML,
}
