package presenter

import "fmt"

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

		// TODO: Should we also validate access to the template file and the template's syntax, too?

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
