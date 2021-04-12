package formats

import (
	"io"

	"github.com/anchore/grype/grype"
)

// Format abstracts the functionality of formatting a grype.Analysis,
// which is useful for downstream Presenters that are ignorant of Grype specifics.
type Format func(grype.Analysis, io.Writer) error
