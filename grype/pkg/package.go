package pkg

import (
	"fmt"

	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// ID represents a unique value for each package added to a package catalog.
type ID string

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	ID           ID
	Name         string            // the package name
	Version      string            // the version of the package
	Locations    []source.Location // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	Language     pkg.Language      // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Licenses     []string
	Type         pkg.Type  // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []pkg.CPE // all possible Common Platform Enumerators
	PURL         string    // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType pkg.MetadataType
	Metadata     interface{} // This is NOT 1-for-1 the syft metadata! Only the select data needed for vulnerability matching
}

func New(p pkg.Package) Package {
	var metadata interface{}

	metadataType := p.MetadataType
	switch metadataType {
	case pkg.DpkgMetadataType:
		if value, ok := p.Metadata.(pkg.DpkgMetadata); ok {
			metadata = DpkgMetadata{Source: value.Source}
		} else {
			log.Warnf("unable to extract DPKG metadata for %s", p)
		}
	case pkg.RpmdbMetadataType:
		if value, ok := p.Metadata.(pkg.RpmdbMetadata); ok {
			metadata = RpmdbMetadata{SourceRpm: value.SourceRpm, Epoch: value.Epoch}
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
				VirtualPath:   value.VirtualPath,
				PomArtifactID: artifact,
				PomGroupID:    group,
				ManifestName:  name,
			}
		} else {
			log.Warnf("unable to extract Java metadata for %s", p)
		}
	case pkg.ApkMetadataType:
		if value, ok := p.Metadata.(pkg.ApkMetadata); ok {
			metadata = ApkMetadata{
				OriginPackage: value.OriginPackage,
			}
		} else {
			log.Warnf("unable to extract APK metadata for %s", p)
		}
	case "":
		// let's try to extract matching-specific information from additional sources other than syft json shapes.
		switch p.Type {
		case pkg.ApkPkg:
			if m := apkMetadataFromPURL(p.PURL); m != nil {
				metadata = *m
				metadataType = pkg.ApkMetadataType
			}
		case pkg.DebPkg:
			if m := dpkgMetadataFromPURL(p.PURL); m != nil {
				metadata = *m
				metadataType = pkg.DpkgMetadataType
			}
		case pkg.RpmPkg:
			if m := rpmdbMetadataFromPURL(p.PURL); m != nil {
				metadata = *m
				metadataType = pkg.RpmdbMetadataType
			}
		}
	}

	return Package{
		ID:           ID(p.ID()),
		Name:         p.Name,
		Version:      p.Version,
		Locations:    p.Locations,
		Licenses:     p.Licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         p.CPEs,
		PURL:         p.PURL,
		MetadataType: metadataType,
		Metadata:     metadata,
	}
}

func FromCatalog(catalog *pkg.Catalog) []Package {
	result := make([]Package, 0, catalog.PackageCount())
	for _, p := range catalog.Sorted() {
		result = append(result, New(p))
	}
	return result
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

func ByID(id ID, pkgs []Package) *Package {
	for _, p := range pkgs {
		if p.ID == id {
			return &p
		}
	}
	return nil
}
