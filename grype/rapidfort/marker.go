// Package rapidfort provides constants and helpers for detecting RapidFort-
// curated container images via the marker file /usr/share/rapidfort/curated.json.
//
// This is a leaf package: it depends only on syft types and is safely imported
// by both the source providers under grype/pkg (which populate the detection
// flag) and the matcher under grype/matcher/rapidfort (which reads it).
package rapidfort

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

// MarkerPath is the marker file whose presence identifies a RapidFort-curated
// image. Consumed by matcher.ApplySelectionPolicy via pkg.Context.IsRapidFortImage.
const MarkerPath = "/usr/share/rapidfort/curated.json"

// HasMarkerInResolver checks a live source resolver for the marker file.
// Callers must invoke before closing the source. nil resolver returns false.
func HasMarkerInResolver(resolver file.PathResolver) bool {
	if resolver == nil {
		return false
	}
	return resolver.HasPath(MarkerPath)
}

// HasMarkerInSBOM checks the SBOM's file catalog for the marker file.
// Best-effort: default syft cataloging does not include the marker path, so
// this returns false unless the SBOM was produced with a file cataloger that
// captured it.
func HasMarkerInSBOM(s *sbom.SBOM) bool {
	if s == nil {
		return false
	}
	for coordinates := range s.Artifacts.FileMetadata {
		if coordinates.RealPath == MarkerPath {
			return true
		}
	}
	return false
}
