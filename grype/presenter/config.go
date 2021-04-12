package presenter

import "fmt"

// config is the presenter domain's configuration data structure.
type config struct {
	format           format
	templateFilePath string
}

// validatedConfig returns a new, validated presenter.config. If a valid config cannot be created using the given input,
// an error is returned.
func validatedConfig(outputFormat, outputTemplateFile string) (config, error) {
	format := parse(outputFormat)

	if format == unknownFormat {
		return config{}, fmt.Errorf("unsupported output format %q, supported formats are: %+v", outputFormat,
			AvailableFormats)
	}

	if format == templateFormat {
		if outputTemplateFile == "" {
			return config{}, fmt.Errorf("must specify path to template file when using %q output format",
				templateFormat)
		}

		// TODO: Should we also validate access to the template file and the template's syntax, too?

		return config{
			format:           format,
			templateFilePath: outputTemplateFile,
		}, nil
	}

	if outputTemplateFile != "" {
		return config{}, fmt.Errorf("specified template file %q, but "+
			"%q output format must be selected in order to use a template file",
			outputTemplateFile, templateFormat)
	}

	return config{
		format: format,
	}, nil
}
