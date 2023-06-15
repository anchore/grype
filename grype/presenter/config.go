package presenter

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"

	presenterTemplate "github.com/anchore/grype/grype/presenter/template"
)

// Config is the presenter domain's configuration data structure.
type Config struct {
	formats          []format
	templateFilePath string
	showSuppressed   bool
}

// ValidatedConfig returns a new, validated presenter.Config. If a valid Config cannot be created using the given input,
// an error is returned.
func ValidatedConfig(outputs []string, defaultFile string, outputTemplateFile string, showSuppressed bool) (Config, error) {
	formats := parseOutputs(outputs, defaultFile)
	hasTemplateFormat := false

	for _, format := range formats {
		if format.id == unknownFormat {
			return Config{}, fmt.Errorf("unsupported output format %q, supported formats are: %+v", format.id,
				AvailableFormats)
		}

		if format.id == templateFormat {
			hasTemplateFormat = true

			if outputTemplateFile == "" {
				return Config{}, fmt.Errorf("must specify path to template file when using %q output format",
					templateFormat)
			}

			if _, err := os.Stat(outputTemplateFile); errors.Is(err, os.ErrNotExist) {
				// file does not exist
				return Config{}, fmt.Errorf("template file %q does not exist",
					outputTemplateFile)
			}

			if _, err := os.ReadFile(outputTemplateFile); err != nil {
				return Config{}, fmt.Errorf("unable to read template file: %w", err)
			}

			if _, err := template.New("").Funcs(presenterTemplate.FuncMap).ParseFiles(outputTemplateFile); err != nil {
				return Config{}, fmt.Errorf("unable to parse template: %w", err)
			}
		}
	}

	if outputTemplateFile != "" && !hasTemplateFormat {
		return Config{}, fmt.Errorf("specified template file %q, but "+
			"%q output format must be selected in order to use a template file",
			outputTemplateFile, templateFormat)
	}

	return Config{
		formats:          formats,
		showSuppressed:   showSuppressed,
		templateFilePath: outputTemplateFile,
	}, nil
}

// parseOptions utility to parse command-line option strings and retain the existing behavior of default format and file
func parseOutputs(outputs []string, defaultFile string) (out []format) {
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

		format := parse(name)
		format.outputFilePath = file
		out = append(out, format)
	}
	return out
}
