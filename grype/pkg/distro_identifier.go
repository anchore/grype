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
		if id.Apply == distro.IdentifierNever {
			continue
		}
		evidence := identifierEvidence(id, s)
		if evidence == "" {
			continue
		}
		newID, ok := id.DistroIDs[d.ID()]
		if !ok {
			continue
		}
		newType, ok := distro.IDMapping[newID]
		if !ok {
			log.WithFields("identifier", id.Name, "distro", newID).Debug("distro identifier maps to an unknown distro ID")
			continue
		}

		log.WithFields("identifier", id.Name, "from", d.ID(), "to", newID, "evidence", evidence).Debug("applying distro identifier")

		// base-distro channels (e.g. esm, eus) are dropped: they would exclude the vendor's channel-less records
		return distro.New(newType, d.Version, "", d.IDLike...)
	}

	return d
}

// identifierEvidence describes what triggers the identifier (a marker file or an image label), or is
// empty when nothing does.
func identifierEvidence(id distro.Identifier, s *sbom.SBOM) string {
	for _, p := range id.MarkerPaths {
		if sbomHasPath(s, p) {
			return "file " + p
		}
	}
	if id.Label.Key == "" {
		return ""
	}
	return imageLabel(s.Source, id.Label)
}

// imageLabel is the first image label m matches, as "label key=value", or empty for none.
func imageLabel(src source.Description, m distro.LabelMatcher) string {
	meta, ok := src.Metadata.(source.ImageMetadata)
	if !ok {
		return ""
	}
	for key, value := range meta.Labels {
		if m.Matches(key, value) {
			return "label " + key + "=" + value
		}
	}
	return ""
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
