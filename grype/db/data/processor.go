package data

import (
	"io"

	"github.com/anchore/grype/grype/db/provider"
)

// Processor takes individual feed group cache files (for select feed groups) and is responsible to producing
// data.Entry objects to be written to the DB.
type Processor interface {
	IsSupported(schemaURL string) bool
	Process(reader io.Reader, state provider.State) ([]Entry, error)
}
