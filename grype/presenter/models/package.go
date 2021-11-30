package models

import (
	"github.com/anchore/grype/grype/pkg"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

// Package is meant to be only the fields that are needed when displaying a single pkg.Package object for the JSON presenter.
type Package struct {
	Name      string                   `json:"name"`
	Version   string                   `json:"version"`
	Type      syftPkg.Type             `json:"type"`
	Locations []syftSource.Coordinates `json:"locations"`
	Language  syftPkg.Language         `json:"language"`
	Licenses  []string                 `json:"licenses"`
	CPEs      []string                 `json:"cpes"`
	PURL      string                   `json:"purl"`
	Metadata  interface{}              `json:"metadata"`
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
	for _, l := range p.Locations {
		coordinates = append(coordinates, l.Coordinates)
	}

	return Package{
		Name:      p.Name,
		Version:   p.Version,
		Locations: coordinates,
		Licenses:  licenses,
		Language:  p.Language,
		Type:      p.Type,
		CPEs:      cpes,
		PURL:      p.PURL,
		Metadata:  p.Metadata,
	}
}
