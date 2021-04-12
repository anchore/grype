package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/grype/grype/presenter/formats/models"

	"github.com/anchore/grype/grype"
)

// The Name of the Format.
const Name = "json"

// Format returns the "json" Format implementation.
func Format(analysis grype.Analysis, output io.Writer) error {
	doc, err := models.NewDocument(analysis)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
