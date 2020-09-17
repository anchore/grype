package cyclonedx

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/anchore/grype/grype/match"

	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/pkg"
	syftCDX "github.com/anchore/syft/syft/presenter/cyclonedx"
	"github.com/anchore/syft/syft/scope"
)

// Presenter writes a CycloneDX report from the given Catalog and Scope contents
type Presenter struct {
	results          match.Matches
	catalog          *pkg.Catalog
	scope            scope.Scope
	metadataProvider vulnerability.MetadataProvider
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results match.Matches, catalog *pkg.Catalog, theScope scope.Scope, metadataProvider vulnerability.MetadataProvider) *Presenter {
	return &Presenter{
		results:          results,
		catalog:          catalog,
		metadataProvider: metadataProvider,
		scope:            theScope,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	bom := NewDocumentFromCatalog(pres.catalog, pres.results, pres.metadataProvider)

	srcObj := pres.scope.Source()

	switch src := srcObj.(type) {
	case scope.DirSource:
		bom.BomDescriptor.Component = &syftCDX.BdComponent{
			Component: syftCDX.Component{
				Type:    "file",
				Name:    src.Path,
				Version: "",
			},
		}
	case scope.ImageSource:
		var imageID string
		var versionStr string
		if len(src.Img.Metadata.Tags) > 0 {
			imageID = src.Img.Metadata.Tags[0].Context().Name()
			versionStr = src.Img.Metadata.Tags[0].TagStr()
		} else {
			imageID = src.Img.Metadata.Digest
		}
		src.Img.Metadata.Tags[0].TagStr()
		bom.BomDescriptor.Component = &syftCDX.BdComponent{
			Component: syftCDX.Component{
				Type:    "container",
				Name:    imageID,
				Version: versionStr,
			},
		}
	default:
		return fmt.Errorf("unsupported source: %T", src)
	}

	encoder := xml.NewEncoder(output)
	encoder.Indent("", "  ")

	_, err := output.Write([]byte(xml.Header))
	if err != nil {
		return err
	}

	err = encoder.Encode(bom)

	if err != nil {
		return err
	}

	return err
}
