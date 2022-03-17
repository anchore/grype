package cyclonedxvex

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	results          match.Matches
	packages         []pkg.Package
	srcMetadata      *source.Metadata
	metadataProvider vulnerability.MetadataProvider
	embedded         bool
	format           cyclonedx.BOMFileFormat
}

// NewPresenter is a *Presenter constructor
func NewPresenter(results match.Matches, packages []pkg.Package, srcMetadata *source.Metadata, metadataProvider vulnerability.MetadataProvider, embedded bool, format cyclonedx.BOMFileFormat) *Presenter {
	return &Presenter{
		results:          results,
		packages:         packages,
		metadataProvider: metadataProvider,
		srcMetadata:      srcMetadata,
		embedded:         embedded,
		format:           format,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	bom, err := NewDocument(pres.packages, pres.results, pres.srcMetadata, pres.metadataProvider)
	if err != nil {
		return err
	}
	encoder := cyclonedx.NewBOMEncoder(output, pres.format)
	encoder.SetPretty(true)

	err = encoder.Encode(bom)

	if err != nil {
		return err
	}

	return err
}
