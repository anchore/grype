package pkg

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// applyDistroIdentifiers returns the identified distro based on source evidence
func applyDistroIdentifiers(s *sbom.SBOM, d *distro.Distro, identifiers []distro.Identifier) *distro.Distro {
	if d == nil {
		return d
	}

	for _, o := range identifiers {
		if o.Apply == distro.ChannelNeverEnabled {
			continue
		}
		if !identifierTriggered(o, s) {
			continue
		}
		newID, ok := o.DistroIDs[d.ID()]
		if !ok {
			continue
		}
		newType, ok := distro.IDMapping[newID]
		if !ok {
			log.WithFields("rule", o.Name, "distro", newID).Warn("distro identifier maps to an unknown distro ID")
			continue
		}

		nd := distro.New(newType, d.Version, "", d.IDLike...)

		// do not inherit base-distro channels (e.g. esm/eus): those describe the base vendor's fix
		// streams and would exclude the identified distro's channel-less OS records from matching
		nd.Channels = o.Channels

		log.WithFields("rule", o.Name, "from", d.ID(), "to", newID).Info("applying source-evidence distro identifier")

		return nd
	}

	return d
}

// identifierTriggered indicates if the scanned source carries any of the identifier's
// evidence: a marker file (via hasPath) or a matching container image label.
func identifierTriggered(o distro.Identifier, s *sbom.SBOM) bool {
	if s != nil {
		for _, p := range o.MarkerPaths {
			if sbomHasPath(s, p) {
				return true
			}
		}

		if o.Label.Key != "" && sourceMatchesLabel(&s.Source, o.Label) {
			return true
		}
	}

	return false
}

// sourceMatchesLabel indicates if the source describes a container image whose config labels
// satisfy the given matcher.
func sourceMatchesLabel(src *source.Description, m distro.LabelMatcher) bool {
	if src == nil {
		return false
	}

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

// sbomHasPath reports whether the SBOM's file catalog contains the given path. Best effort:
// default syft cataloging does not capture arbitrary file paths, so this only finds markers when
// the SBOM was produced with a file cataloger that recorded them.
func sbomHasPath(s *sbom.SBOM, path string) bool {
	if s == nil {
		return false
	}
	for coordinates := range s.Artifacts.FileMetadata {
		if coordinates.RealPath == path {
			return true
		}
	}
	return false
}
