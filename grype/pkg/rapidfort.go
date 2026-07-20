package pkg

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

// RapidFortMarkerPath is the absolute path of the marker file that the
// RapidFort curation pipeline writes into every image it produces. Its presence
// is treated as authoritative: if the file is there, the image is RapidFort-
// curated and the RapidFort matcher takes over (see matcher.ApplySelectionPolicy).
//
// Why a file and not a label? A Docker label ("maintainer=RapidFort...") can be
// added, altered, or stripped by any subsequent `docker build` step, and doesn't
// require actual RapidFort tooling — it's cheap to spoof. The marker file, in
// contrast, is written into a specific layer as part of the curation build; it
// travels with the image contents rather than with mutable metadata.
const RapidFortMarkerPath = "/usr/share/rapidfort/curated.json"

// hasRapidFortMarkerInResolver reports whether the RapidFort curation marker
// file exists in the given source's file resolver. It is intended for callers
// that hold a live source handle (e.g. during a container-image or directory
// scan). Passing a nil resolver returns false.
//
// The resolver must remain valid for the duration of this call; callers must
// invoke it before closing the underlying source.
func hasRapidFortMarkerInResolver(resolver file.PathResolver) bool {
	if resolver == nil {
		return false
	}
	return resolver.HasPath(RapidFortMarkerPath)
}

// hasRapidFortMarkerInSBOM reports whether the RapidFort curation marker file
// is present in the file catalog of the given SBOM. This is a best-effort
// detection path used for scans where no live source resolver is available
// (SBOM-based scans, Zarf packages).
//
// Note: syft's default cataloging does not include arbitrary files such as
// /usr/share/rapidfort/curated.json unless the SBOM was generated with a
// file cataloger that captured this path. When the marker file is not present
// in the SBOM catalog this function returns false, meaning RapidFort matcher
// selection will not activate for that scan.
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
