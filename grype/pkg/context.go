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

	// IsRapidFortImage is true when rapidfort.MarkerPath was found on the source
	// (live scans) or in the SBOM's file catalog (SBOM/Zarf scans, best effort).
	// Populated by the package providers; read by matcher.ApplySelectionPolicy.
	IsRapidFortImage bool
}
