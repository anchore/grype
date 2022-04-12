package models

import (
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

// Package is meant to be only the fields that are needed when displaying a single pkg.Package object for the JSON presenter.
type Package struct {
	Name         string                   `json:"name"`
	Version      string                   `json:"version"`
	Type         syftPkg.Type             `json:"type"`
	Locations    []syftSource.Coordinates `json:"locations"`
	Language     syftPkg.Language         `json:"language"`
	Licenses     []string                 `json:"licenses"`
	CPEs         []string                 `json:"cpes"`
	PURL         string                   `json:"purl"`
	Upstreams    []UpstreamPackage        `json:"upstreams"`
	MetadataType pkg.MetadataType         `json:"metadataType,omitempty"`
	Metadata     interface{}              `json:"metadata,omitempty"`
}

type UpstreamPackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

func newPackage(p pkg.Package) Package {
	var cpes = make([]string, 0)
	for _, c := range p.CPEs {
		cpes = append(cpes, c.BindToFmtString())
	}

	licenses := p.Licenses
	if licenses == nil {
		licenses = make([]string, 0)
	}

	var coordinates = make([]syftSource.Coordinates, 0)
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
		Name:         p.Name,
		Version:      p.Version,
		Locations:    coordinates,
		Licenses:     licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		Upstreams:    upstreams,
		MetadataType: p.MetadataType,
		Metadata:     p.Metadata,
	}
}
