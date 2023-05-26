package cyclonedx

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/formats/common/cyclonedxhelpers"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/nextlinux/griffon/griffon/match"
	"github.com/nextlinux/griffon/griffon/pkg"
	"github.com/nextlinux/griffon/griffon/presenter/models"
	"github.com/nextlinux/griffon/griffon/vulnerability"
	"github.com/nextlinux/griffon/internal"
	"github.com/nextlinux/griffon/internal/version"
)

// Presenter writes a CycloneDX report from the given Matches and Scope contents
type Presenter struct {
	results          match.Matches
	packages         []pkg.Package
	srcMetadata      *source.Metadata
	metadataProvider vulnerability.MetadataProvider
	format           cyclonedx.BOMFileFormat
	sbom             *sbom.SBOM
}

// NewPresenter is a *Presenter constructor
func NewJSONPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		srcMetadata:      pb.Context.Source,
		sbom:             pb.SBOM,
		format:           cyclonedx.BOMFileFormatJSON,
	}
}

// NewPresenter is a *Presenter constructor
func NewXMLPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		results:          pb.Matches,
		packages:         pb.Packages,
		metadataProvider: pb.MetadataProvider,
		srcMetadata:      pb.Context.Source,
		sbom:             pb.SBOM,
		format:           cyclonedx.BOMFileFormatXML,
	}
}

// Present creates a CycloneDX-based reporting
func (pres *Presenter) Present(output io.Writer) error {
	// note: this uses the syft cyclondx helpers to create
	// a consistent cyclondx BOM across syft and griffon
	cyclonedxBOM := cyclonedxhelpers.ToFormatModel(*pres.sbom)

	// empty the tool metadata and add griffon metadata
	versionInfo := version.FromBuild()
	cyclonedxBOM.Metadata.Tools = &[]cyclonedx.Tool{
		{
			Vendor:  "anchore",
			Name:    internal.ApplicationName,
			Version: versionInfo.Version,
		},
	}

	vulns := make([]cyclonedx.Vulnerability, 0)
	for _, m := range pres.results.Sorted() {
		v, err := NewVulnerability(m, pres.metadataProvider)
		if err != nil {
			continue
		}
		vulns = append(vulns, v)
	}
	cyclonedxBOM.Vulnerabilities = &vulns
	enc := cyclonedx.NewBOMEncoder(output, pres.format)
	enc.SetPretty(true)
	enc.SetEscapeHTML(false)

	return enc.Encode(cyclonedxBOM)
}
