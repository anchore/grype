package cmd

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"

	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/sbom"
)

// makeWriter creates a sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func MakeWriter(outputs []string, defaultFile, templateFilePath string) (sbom.Writer, error) {
	outputOptions, err := parseOutputs(outputs, defaultFile, templateFilePath)
	if err != nil {
		return nil, err
	}

	writer, err := sbom.NewWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseOptions utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOutputs(outputs []string, defaultFile, templateFilePath string) (out []sbom.WriterOption, errs error) {
	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, table.ID.String())
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format name is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output formatName, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		format := formats.ByName(name)
		if format == nil {
			errs = multierror.Append(errs, fmt.Errorf(`unsupported output format "%s", supported formats are: %+v`, name, formats.AllIDs()))
			continue
		}

		if tmpl, ok := format.(template.OutputFormat); ok {
			tmpl.SetTemplatePath(templateFilePath)
			format = tmpl
		}

		out = append(out, sbom.NewWriterOption(format, file))
	}
	return out, errs
}
