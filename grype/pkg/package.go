package pkg

import (
	"fmt"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// ID represents a unique value for each package added to a package catalog.
type ID int64

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	id        ID
	Name      string            // the package name
	Version   string            // the version of the package
	Locations []source.Location // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Language  pkg.Language      // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Licenses  []string
	Type      pkg.Type    // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs      []pkg.CPE   // all possible Common Platform Enumerators
	PURL      string      // the Package URL (see https://github.com/package-url/purl-spec)
	Metadata  interface{} // This is NOT the syft metadata! Only the select data needed for vulnerability matching
}

func New(p *pkg.Package) Package {
	var metadata interface{}

	switch p.MetadataType {
	case pkg.DpkgMetadataType:
		if value, ok := p.Metadata.(pkg.DpkgMetadata); ok {
			metadata = DpkgMetadata{Source: value.Source}
		} else {
			log.Warnf("unable to extract DPKG metadata for %s", p)
		}
	case pkg.RpmdbMetadataType:
		if value, ok := p.Metadata.(pkg.RpmdbMetadata); ok {
			metadata = RpmdbMetadata{SourceRpm: value.SourceRpm}
		} else {
			log.Warnf("unable to extract RPM metadata for %s", p)
		}
	case pkg.JavaMetadataType:
		if value, ok := p.Metadata.(pkg.JavaMetadata); ok {
			var artifact, group, name string
			if value.PomProperties != nil {
				artifact = value.PomProperties.ArtifactID
				group = value.PomProperties.GroupID
			}
			if value.Manifest != nil {
				if n, ok := value.Manifest.Main["Name"]; ok {
					name = n
				}
			}

			metadata = JavaMetadata{
				PomArtifactID: artifact,
				PomGroupID:    group,
				ManifestName:  name,
			}
		} else {
			log.Warnf("unable to extract Java metadata for %s", p)
		}
	}

	return Package{
		id:        ID(p.ID()),
		Name:      p.Name,
		Version:   p.Version,
		Locations: p.Locations,
		Licenses:  p.Licenses,
		Language:  p.Language,
		Type:      p.Type,
		CPEs:      p.CPEs,
		PURL:      p.PURL,
		Metadata:  metadata,
	}
}

func FromCatalog(catalog *pkg.Catalog) []Package {
	var result = make([]Package, catalog.PackageCount())
	for i, p := range catalog.Sorted() {
		result[i] = New(p)
	}
	return result
}

// ID returns the package ID, which is unique relative to a package catalog.
func (p Package) ID() ID {
	return p.id
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

func ByID(id ID, pkgs []Package) *Package {
	for _, p := range pkgs {
		if p.ID() == id {
			return &p
		}
	}
	return nil
}
