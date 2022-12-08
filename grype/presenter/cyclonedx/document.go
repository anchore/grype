package cyclonedx

import (
	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/source"
)

// NewDocument returns a CycloneDX Document object populated with the SBOM and vulnerability findings.
func NewDocument(
	packages []pkg.Package,
	matches match.Matches,
	srcMetadata *source.Metadata,
	provider vulnerability.MetadataProvider,
) *cyclonedx.BOM {
	cdxBom := cyclonedx.NewBOM()
	return cdxBom
}
