package presenter

import (
	"errors"
	"fmt"
	"os"
	"text/template"

	presenterTemplate "github.com/anchore/grype/grype/presenter/template"
)

// Config is the presenter domain's configuration data structure.
type Config struct {
	format           format
	templateFilePath string
}

// ValidatedConfig returns a new, validated presenter.Config. If a valid Config cannot be created using the given input,
// an error is returned.
func ValidatedConfig(output, outputTemplateFile string) (Config, error) {
	format := parse(output)

	if format == unknownFormat {
		return Config{}, fmt.Errorf("unsupported output format %q, supported formats are: %+v", output,
			AvailableFormats)
	}

	if format == templateFormat {
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

		return Config{
			format:           format,
			templateFilePath: outputTemplateFile,
		}, nil
	}

	if outputTemplateFile != "" {
		return Config{}, fmt.Errorf("specified template file %q, but "+
			"%q output format must be selected in order to use a template file",
			outputTemplateFile, templateFormat)
	}

	return Config{
		format: format,
	}, nil
}
