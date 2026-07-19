package pkg

import (
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

// RapidFortMarkerPath is the absolute path of the marker file present on every
// RapidFort-curated container image. Its presence unambiguously identifies an
// image as RapidFort-curated and drives the RapidFort matcher selection in
// matcher.ApplySelectionPolicy.
//
// This constant is the single source of truth for RapidFort image detection;
// prior versions of grype relied on the "maintainer" Docker label, which was
// spoofable and coupled RapidFort identity to metadata rather than image
// contents.
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
