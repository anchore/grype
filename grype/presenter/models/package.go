package models

import (
	"github.com/anchore/grype/grype/internal/packagemetadata"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Package is meant to be only the fields that are needed when displaying a single pkg.Package object for the JSON presenter.
type Package struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Type         syftPkg.Type       `json:"type"`
	Locations    []file.Coordinates `json:"locations"`
	Language     syftPkg.Language   `json:"language"`
	Licenses     []string           `json:"licenses"`
	CPEs         []string           `json:"cpes"`
	PURL         string             `json:"purl"`
	Upstreams    []UpstreamPackage  `json:"upstreams"`
	MetadataType string             `json:"metadataType,omitempty"`
	Metadata     interface{}        `json:"metadata,omitempty"`
}

type UpstreamPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

func newPackage(p pkg.Package) Package {
	var cpes = make([]string, 0)
	for _, c := range p.CPEs {
		cpes = append(cpes, c.Attributes.BindToFmtString())
	}

	licenses := p.Licenses
	if licenses == nil {
		licenses = make([]string, 0)
	}

	var coordinates = make([]file.Coordinates, 0)
	locations := p.Locations.ToSlice()
	for _, l := range locations {
		coordinates = append(coordinates, l.Coordinates)
	}

	var upstreams = make([]UpstreamPackage, 0)
	for _, u := range p.Upstreams {
		upstreams = append(upstreams, UpstreamPackage{
			Name:    u.Name,
			Version: u.Version,
		})
	}

	return Package{
		ID:           string(p.ID),
		Name:         p.Name,
		Version:      p.Version,
		Locations:    coordinates,
		Licenses:     licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		Upstreams:    upstreams,
		MetadataType: packagemetadata.JSONName(p.Metadata),
		Metadata:     p.Metadata,
	}
}
