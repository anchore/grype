package pkg

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

// RapidFortMarkerPath is the marker file whose presence identifies a
// RapidFort-curated image. Consumed by matcher.ApplySelectionPolicy.
const RapidFortMarkerPath = "/usr/share/rapidfort/curated.json"

// hasRapidFortMarkerInResolver checks a live source resolver for the marker file.
// Callers must invoke before closing the source. nil resolver returns false.
func hasRapidFortMarkerInResolver(resolver file.PathResolver) bool {
	if resolver == nil {
		return false
	}
	return resolver.HasPath(RapidFortMarkerPath)
}

// hasRapidFortMarkerInSBOM checks the SBOM's file catalog for the marker file.
// Best-effort: default syft cataloging does not include the marker path, so
// this returns false unless the SBOM was produced with a file cataloger that
// captured it.
func hasRapidFortMarkerInSBOM(s *sbom.SBOM) bool {
	if s == nil {
		return false
	}
	for coordinates := range s.Artifacts.FileMetadata {
		if coordinates.RealPath == RapidFortMarkerPath {
			return true
		}
	}
	return false
}
