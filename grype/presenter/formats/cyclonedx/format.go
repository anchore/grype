package cyclonedx

import (
	"encoding/xml"
	"io"

	"github.com/anchore/grype/grype"
)

// The Name of the Format.
const Name = "cyclonedx"

// Format returns the "cyclonedx" Format implementation.
func Format(analysis grype.Analysis, output io.Writer) error {
	bom, err := NewDocument(analysis.Packages, analysis.Matches, analysis.Context.Source, analysis.MetadataProvider)
	if err != nil {
		return err
	}

	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	_, err = output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = encoder.Encode(bom)

	if err != nil {
		return err
	}

	return err
}
