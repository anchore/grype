package cyclonedx

import (
	"encoding/xml"
	"io"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Catalog and Scope contents
type Presenter struct {
	results          match.Matches
	catalog          *pkg.Catalog
	srcMetadata      source.Metadata
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results match.Matches, catalog *pkg.Catalog, srcMetadata source.Metadata, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		results:          results,
		catalog:          catalog,
		metadataProvider: metadataProvider,
		srcMetadata:      srcMetadata,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	bom, err := NewDocument(pres.catalog, pres.results, pres.srcMetadata, pres.metadataProvider)
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
