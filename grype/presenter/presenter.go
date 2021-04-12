package presenter

import (
	"io"

	"github.com/anchore/grype/grype/presenter/formats"

	"github.com/anchore/grype/grype"
)

// Presenter is the main interface other Presenters need to implement
type Presenter func(io.Writer) error

// Apply the given Format to a grype.Analysis and return the operation as a Presenter.
func Apply(format formats.Format, analysis grype.Analysis) Presenter {
	return func(output io.Writer) error {
		return format(analysis, output)
	}
}
