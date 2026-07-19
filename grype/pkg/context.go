package pkg

import (
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/syft/syft/source"
)

type Context struct {
	Source *source.Description
	Distro *distro.Distro
	// DistroDetectionFailed is true when linux release info was present but
	// the distro type could not be determined (e.g., unknown distro ID)
	DistroDetectionFailed bool

	// IsRapidFortImage is true when the scan target has been identified as a
	// RapidFort-curated container image. Identification is performed at package-
	// provider time by checking for the marker file at RapidFortMarkerPath in
	// the source's file resolver (for live image/directory scans) or in the
	// SBOM's file catalog (for SBOM- and Zarf-based scans, best effort — only
	// true when the marker file was cataloged during SBOM generation).
	//
	// This flag replaces the earlier heuristic based on the "maintainer" Docker
	// label. Consumers should treat it as authoritative for downstream matcher
	// selection (see matcher.ApplySelectionPolicy).
	IsRapidFortImage bool
}
