package pkg

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// applyDistroIdentifiers returns d remapped by the first identifier the source evidence triggers.
func applyDistroIdentifiers(s *sbom.SBOM, d *distro.Distro, identifiers []distro.Identifier) *distro.Distro {
	if d == nil || s == nil {
		return d
	}

	for _, id := range identifiers {
		if id.Apply == distro.IdentifierNever || !identifierTriggered(id, s) {
			continue
		}
		newID, ok := id.DistroIDs[d.ID()]
		if !ok {
			continue
		}
		newType, ok := distro.IDMapping[newID]
		if !ok {
			log.WithFields("identifier", id.Name, "distro", newID).Warn("distro identifier maps to an unknown distro ID")
			continue
		}

		log.WithFields("identifier", id.Name, "from", d.ID(), "to", newID).Info("applying distro identifier")

		// base-distro channels (e.g. esm, eus) are dropped: they would exclude the vendor's channel-less records
		return distro.New(newType, d.Version, "", d.IDLike...)
	}

	return d
}

func identifierTriggered(id distro.Identifier, s *sbom.SBOM) bool {
	for _, p := range id.MarkerPaths {
		if sbomHasPath(s, p) {
			return true
		}
	}
	return id.Label.Key != "" && imageHasLabel(s.Source, id.Label)
}

func imageHasLabel(src source.Description, m distro.LabelMatcher) bool {
	meta, ok := src.Metadata.(source.ImageMetadata)
	if !ok {
		return false
	}
	for key, value := range meta.Labels {
		if m.Matches(key, value) {
			return true
		}
	}
	return false
}

// sbomHasPath reports whether the SBOM's file catalog contains path. Default syft cataloging does
// not record arbitrary files, so this only finds markers a file cataloger recorded.
func sbomHasPath(s *sbom.SBOM, path string) bool {
	for coordinates := range s.Artifacts.FileMetadata {
		if coordinates.RealPath == path {
			return true
		}
	}
	return false
}
