package cyclonedxvex

import (
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal"
	"github.com/anchore/grype/internal/version"
	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/source"
)

// NewDocument returns a CycloneDX Document object populated with the SBOM and vulnerability findings.
func NewDocument(packages []pkg.Package, matches match.Matches, srcMetadata *source.Metadata, provider vulnerability.MetadataProvider) (*cyclonedx.BOM, error) {
	versionInfo := version.FromBuild()
	doc := cyclonedx.NewBOM()
	doc.SerialNumber = uuid.New().URN()
	if srcMetadata != nil {
		doc.Metadata = NewBomMetadata(internal.ApplicationName, versionInfo.Version, srcMetadata)
	}

	// attach matches
	components := []cyclonedx.Component{}
	vulnerabilities := []cyclonedx.Vulnerability{}

	for _, p := range packages {
		component := getComponent(p)
		pkgMatches := matches.GetByPkgID(p.ID)

		if len(pkgMatches) > 0 {
			for _, m := range pkgMatches {
				v, err := NewVulnerability(m, provider)
				if err != nil {
					return &cyclonedx.BOM{}, err
				}
				v.Affects = &[]cyclonedx.Affects{
					{
						Ref: component.BOMRef,
					},
				}
				vulnerabilities = append(vulnerabilities, v)
			}
		}
		// add a *copy* of the Component to the bom document
		components = append(components, component)
	}
	doc.Components = &components
	doc.Vulnerabilities = &vulnerabilities

	return doc, nil
}

func getComponent(p pkg.Package) cyclonedx.Component {
	bomRef := string(p.ID)
	// try and parse the PURL if possible and append syft id to it, to make
	// the purl unique in the BOM.
	// TODO: In the future we may want to dedupe by PURL and combine components with
	// the same PURL while preserving their unique metadata.
	if parsedPURL, err := packageurl.FromString(p.PURL); err == nil {
		parsedPURL.Qualifiers = append(parsedPURL.Qualifiers, packageurl.Qualifier{Key: "package-id", Value: string(p.ID)})
		bomRef = parsedPURL.ToString()
	}
	// make a new Component (by value)
	component := cyclonedx.Component{
		Type:       "library", // TODO: this is not accurate, syft does the same thing
		Name:       p.Name,
		Version:    p.Version,
		PackageURL: p.PURL,
		BOMRef:     bomRef,
	}

	var licenses cyclonedx.Licenses
	for _, licenseName := range p.Licenses {
		licenses = append(licenses, cyclonedx.LicenseChoice{
			License: &cyclonedx.License{
				Name: licenseName,
			},
		})
	}
	if len(licenses) > 0 {
		// adding licenses to the Component
		component.Licenses = &licenses
	}
	return component
}
